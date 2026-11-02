use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::fakeip::FakeIpManager;
use crate::outbound::{handle_direct, handle_http_proxy, handle_socks5_proxy};
use crate::rules::{RuleSet, Target};

pub struct TproxyServer {
    listen_addr: SocketAddr,
    fakeip_manager: FakeIpManager,
    rules: RuleSet,
}

impl TproxyServer {
    pub fn new(listen_addr: SocketAddr, fakeip_manager: FakeIpManager, rules: RuleSet) -> Self {
        TproxyServer {
            listen_addr,
            fakeip_manager,
            rules,
        }
    }

    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let std_listener = self.create_transparent_listener()?;
        let listener = TcpListener::from_std(std_listener)?;
        info!("TPROXY server listening on {}", self.listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        this.handle_connection(stream, peer_addr).await;
                    });
                }
                Err(e) => {
                    error!("TPROXY accept error: {}", e);
                }
            }
        }
    }

    fn create_transparent_listener(&self) -> io::Result<std::net::TcpListener> {
        let domain = if self.listen_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        let _ = socket.set_reuse_port(true);
        socket.set_nonblocking(true)?;

        #[cfg(target_os = "linux")]
        {
            let fd = socket.as_raw_fd();
            let opt: libc::c_int = 1;
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                warn!(
                    "Failed to set IP_TRANSPARENT on socket (CAP_NET_ADMIN required): {}. Continuing anyway...",
                    err
                );
            } else {
                debug!("Enabled IP_TRANSPARENT on TPROXY listening socket");
            }
        }

        socket.bind(&self.listen_addr.into())?;
        socket.listen(1024)?;
        Ok(socket.into())
    }

    async fn handle_connection(&self, stream: TcpStream, peer_addr: SocketAddr) {
        // In Linux TPROXY with IP_TRANSPARENT, local_addr() returns the original destination!
        let orig_dst = match stream.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                debug!("Failed to get local_addr from stream: {}", e);
                return;
            }
        };

        let dst_ip = match orig_dst.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                debug!("Non-IPv4 connection received from {}: dropping", peer_addr);
                return;
            }
        };

        // Original request dst ip MUST be in fake ip range
        if !self.fakeip_manager.is_fake_ip(&dst_ip) {
            debug!(
                "Dst IP {} not in fake IP range (from {}): dropping connection",
                dst_ip, peer_addr
            );
            return;
        }

        // If request ip is not a recognized fake ip (known origin domain), drop connection
        let domain = match self.fakeip_manager.get_domain(&dst_ip) {
            Some(d) => d,
            None => {
                debug!(
                    "Unrecognized fake IP {} (from {}): dropping connection",
                    dst_ip, peer_addr
                );
                return;
            }
        };

        let dst_port = orig_dst.port();
        let target = self.rules.match_domain(&domain);
        debug!(
            "TPROXY connection from {} -> {} ({}:{}): target={}",
            peer_addr, dst_ip, domain, dst_port, target
        );

        match target {
            Target::Reject => {
                debug!(
                    "Rejecting connection to {} ({}:{})",
                    domain, dst_ip, dst_port
                );
                // Drop stream immediately (will send RST / FIN)
            }
            Target::Direct => {
                self.fakeip_manager.inc_conn(&dst_ip);
                if let Err(e) = handle_direct(stream, &domain, dst_port).await {
                    debug!("Direct outbound error for {}:{}: {}", domain, dst_port, e);
                }
                self.fakeip_manager.dec_conn(&dst_ip);
            }
            Target::Http(proxy) => {
                self.fakeip_manager.inc_conn(&dst_ip);
                if let Err(e) = handle_http_proxy(stream, proxy, &domain, dst_port).await {
                    debug!(
                        "HTTP proxy outbound error for {}:{}: {}",
                        domain, dst_port, e
                    );
                }
                self.fakeip_manager.dec_conn(&dst_ip);
            }
            Target::Socks5(proxy) => {
                self.fakeip_manager.inc_conn(&dst_ip);
                if let Err(e) = handle_socks5_proxy(stream, proxy, &domain, dst_port).await {
                    debug!(
                        "SOCKS5 proxy outbound error for {}:{}: {}",
                        domain, dst_port, e
                    );
                }
                self.fakeip_manager.dec_conn(&dst_ip);
            }
        }
    }
}
