use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::fakeip::FakeIpManager;
use crate::outbound::{
    decode_socks5_udp_packet, encode_socks5_udp_packet, handle_direct, handle_http_proxy,
    handle_socks5_proxy, socks5_udp_associate,
};
use crate::rules::{RuleSet, Target};

pub struct TproxyServer {
    listen_addr: SocketAddr,
    fakeip_manager: FakeIpManager,
    rules: RuleSet,
    egress_mark: Option<u32>,
}

type UdpSessionMap = Arc<parking_lot::Mutex<HashMap<(SocketAddr, SocketAddr), tokio::sync::mpsc::Sender<Vec<u8>>>>>;

impl TproxyServer {
    pub fn new(
        listen_addr: SocketAddr,
        fakeip_manager: FakeIpManager,
        rules: RuleSet,
        egress_mark: Option<u32>,
    ) -> Self {
        TproxyServer {
            listen_addr,
            fakeip_manager,
            rules,
            egress_mark,
        }
    }

    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let this_tcp = self.clone();
        let tcp_task = tokio::spawn(async move {
            if let Err(e) = this_tcp.run_tcp().await {
                error!("TPROXY TCP server error: {}", e);
            }
        });

        let this_udp = self.clone();
        let udp_task = tokio::spawn(async move {
            if let Err(e) = this_udp.run_udp().await {
                error!("TPROXY UDP server error: {}", e);
            }
        });

        tokio::select! {
            res = tcp_task => {
                if let Err(e) = res {
                    error!("TPROXY TCP task terminated: {}", e);
                }
            }
            res = udp_task => {
                if let Err(e) = res {
                    error!("TPROXY UDP task terminated: {}", e);
                }
            }
        }
        Ok(())
    }

    async fn run_tcp(&self) -> io::Result<()> {
        let std_listener = self.create_transparent_listener()?;
        let listener = TcpListener::from_std(std_listener)?;
        info!("TPROXY TCP server listening on {}", self.listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let fakeip_mgr = self.fakeip_manager.clone();
                    let rules = self.rules.clone();
                    let egress_mark = self.egress_mark;
                    tokio::spawn(async move {
                        handle_tcp_connection(stream, peer_addr, fakeip_mgr, rules, egress_mark).await;
                    });
                }
                Err(e) => {
                    error!("TPROXY TCP accept error: {}", e);
                }
            }
        }
    }

    async fn run_udp(&self) -> io::Result<()> {
        let std_socket = self.create_transparent_udp_listener()?;
        let socket = UdpSocket::from_std(std_socket)?;
        info!("TPROXY UDP server listening on {}", self.listen_addr);

        let sessions: UdpSessionMap = Arc::new(parking_lot::Mutex::new(HashMap::new()));

        // Periodic pruning of closed / idle sessions
        let prune_sessions = sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let mut map = prune_sessions.lock();
                map.retain(|_, tx| !tx.is_closed());
            }
        });

        let mut buf = vec![0u8; 65535];
        loop {
            if socket.readable().await.is_err() {
                continue;
            }

            let (n, peer_addr, orig_dst) = match socket.try_io(tokio::io::Interest::READABLE, || {
                recv_msg_with_orig_dst(socket.as_raw_fd(), &mut buf, self.listen_addr)
            }) {
                Ok(res) => res,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    error!("TPROXY UDP recv error: {}", e);
                    continue;
                }
            };

            let payload = buf[..n].to_vec();
            self.handle_udp_packet(peer_addr, orig_dst, payload, &sessions)
                .await;
        }
    }

    async fn handle_udp_packet(
        &self,
        peer_addr: SocketAddr,
        orig_dst: SocketAddr,
        payload: Vec<u8>,
        sessions: &UdpSessionMap,
    ) {
        // Fast path: send to active session
        {
            let map = sessions.lock();
            if let Some(tx) = map.get(&(peer_addr, orig_dst)) {
                if tx.try_send(payload.clone()).is_ok() {
                    return;
                }
            }
        }

        let dst_ip = orig_dst.ip();
        let dst_port = orig_dst.port();
        let is_fake = self.fakeip_manager.is_fake_ip(&dst_ip);

        let (target, target_host) = if is_fake {
            let domain = match self.fakeip_manager.get_domain(&dst_ip) {
                Some(d) => d,
                None => {
                    debug!(
                        "Unrecognized fake IP {} in UDP from {}: dropping",
                        dst_ip, peer_addr
                    );
                    return;
                }
            };
            let target = self.rules.match_domain(&domain).clone();
            (target, domain)
        } else {
            let target = self.rules.match_ip(&dst_ip).clone();
            if matches!(target, Target::Reject) {
                debug!(
                    "Dst IP {} in UDP from {} not accepted by IP rules: dropping",
                    dst_ip, peer_addr
                );
                return;
            }
            (target, dst_ip.to_string())
        };

        match target {
            Target::Reject => {
                debug!(
                    "Rejecting UDP packet to {} ({}:{})",
                    target_host, dst_ip, dst_port
                );
            }
            Target::Http(_) => {
                debug!(
                    "HTTP proxy does not support UDP; dropping packet to {}:{}",
                    target_host, dst_port
                );
            }
            Target::Socks5 { udp: false, .. } => {
                debug!(
                    "SOCKS5 proxy has ?udp=0 (no UDP support); rejecting UDP packet to {}:{}",
                    target_host, dst_port
                );
            }
            Target::Direct => {
                let reply_socket = match create_transparent_reply_socket(
                    orig_dst,
                    peer_addr,
                    self.egress_mark,
                ) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        debug!(
                            "Failed to create transparent UDP reply socket for {} -> {}: {}",
                            orig_dst, peer_addr, e
                        );
                        return;
                    }
                };

                let real_dst = if is_fake {
                    match tokio::net::lookup_host((target_host.as_str(), dst_port)).await {
                        Ok(mut addrs) => match addrs.next() {
                            Some(a) => a,
                            None => {
                                debug!("No addresses found for direct UDP target {}", target_host);
                                return;
                            }
                        },
                        Err(e) => {
                            debug!(
                                "DNS lookup failed for direct UDP target {}: {}",
                                target_host, e
                            );
                            return;
                        }
                    }
                } else {
                    orig_dst
                };

                let outbound_socket =
                    match create_direct_outbound_socket(real_dst, self.egress_mark) {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            debug!(
                                "Failed to create direct outbound UDP socket to {}: {}",
                                real_dst, e
                            );
                            return;
                        }
                    };

                let (tx, rx) = tokio::sync::mpsc::channel(64);
                let _ = tx.try_send(payload);
                sessions.lock().insert((peer_addr, orig_dst), tx);

                let fakeip_mgr = self.fakeip_manager.clone();
                tokio::spawn(async move {
                    if is_fake {
                        fakeip_mgr.inc_conn(&dst_ip);
                    }
                    run_direct_udp_session(rx, reply_socket, outbound_socket).await;
                    if is_fake {
                        fakeip_mgr.dec_conn(&dst_ip);
                    }
                });
            }
            Target::Socks5 {
                addr: proxy_addr,
                udp: true,
            } => {
                let reply_socket = match create_transparent_reply_socket(
                    orig_dst,
                    peer_addr,
                    self.egress_mark,
                ) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        debug!(
                            "Failed to create transparent UDP reply socket for {} -> {}: {}",
                            orig_dst, peer_addr, e
                        );
                        return;
                    }
                };

                let (tx, rx) = tokio::sync::mpsc::channel(64);
                let _ = tx.try_send(payload);
                sessions.lock().insert((peer_addr, orig_dst), tx);

                let fakeip_mgr = self.fakeip_manager.clone();
                let egress_mark = self.egress_mark;
                tokio::spawn(async move {
                    if is_fake {
                        fakeip_mgr.inc_conn(&dst_ip);
                    }
                    run_socks5_udp_session(
                        rx,
                        reply_socket,
                        proxy_addr,
                        target_host,
                        dst_port,
                        egress_mark,
                    )
                    .await;
                    if is_fake {
                        fakeip_mgr.dec_conn(&dst_ip);
                    }
                });
            }
        }
    }

    fn create_transparent_listener(&self) -> io::Result<std::net::TcpListener> {
        let is_ipv6 = self.listen_addr.is_ipv6();
        let domain = if is_ipv6 {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        let _ = socket.set_reuse_port(true);
        socket.set_nonblocking(true)?;

        if is_ipv6 {
            let _ = socket.set_only_v6(false);
        }

        #[cfg(target_os = "linux")]
        {
            let fd = socket.as_raw_fd();
            let opt: libc::c_int = 1;
            unsafe {
                let ret_v4 = libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
                let ret_v6 = if is_ipv6 {
                    libc::setsockopt(
                        fd,
                        libc::SOL_IPV6,
                        libc::IPV6_TRANSPARENT,
                        &opt as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&opt) as libc::socklen_t,
                    )
                } else {
                    0
                };

                if ret_v4 != 0 && ret_v6 != 0 {
                    let err = io::Error::last_os_error();
                    warn!(
                        "Failed to set IP_TRANSPARENT on TCP socket (CAP_NET_ADMIN required): {}. Continuing anyway...",
                        err
                    );
                } else {
                    debug!("Enabled IP_TRANSPARENT on TPROXY TCP listening socket");
                }
            }
        }

        socket.bind(&self.listen_addr.into())?;
        socket.listen(1024)?;
        Ok(socket.into())
    }

    fn create_transparent_udp_listener(&self) -> io::Result<std::net::UdpSocket> {
        let is_ipv6 = self.listen_addr.is_ipv6();
        let domain = if is_ipv6 {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        let _ = socket.set_reuse_port(true);
        socket.set_nonblocking(true)?;

        if is_ipv6 {
            let _ = socket.set_only_v6(false);
        }

        #[cfg(target_os = "linux")]
        {
            let fd = socket.as_raw_fd();
            let opt: libc::c_int = 1;
            unsafe {
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
                if is_ipv6 {
                    let _ = libc::setsockopt(
                        fd,
                        libc::SOL_IPV6,
                        libc::IPV6_TRANSPARENT,
                        &opt as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&opt) as libc::socklen_t,
                    );
                }

                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_RECVORIGDSTADDR,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
                if is_ipv6 {
                    let _ = libc::setsockopt(
                        fd,
                        libc::SOL_IPV6,
                        libc::IPV6_RECVORIGDSTADDR,
                        &opt as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&opt) as libc::socklen_t,
                    );
                }

                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_PKTINFO,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
            }
        }

        socket.bind(&self.listen_addr.into())?;
        Ok(socket.into())
    }
}

async fn handle_tcp_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    fakeip_manager: FakeIpManager,
    rules: RuleSet,
    egress_mark: Option<u32>,
) {
    let orig_dst = match stream.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            debug!("Failed to get local_addr from stream: {}", e);
            return;
        }
    };

    let dst_ip = orig_dst.ip();
    let dst_port = orig_dst.port();
    let is_fake = fakeip_manager.is_fake_ip(&dst_ip);

    let (target, target_host) = if is_fake {
        let domain = match fakeip_manager.get_domain(&dst_ip) {
            Some(d) => d,
            None => {
                debug!(
                    "Unrecognized fake IP {} (from {}): dropping connection",
                    dst_ip, peer_addr
                );
                return;
            }
        };
        let target = rules.match_domain(&domain).clone();
        (target, domain)
    } else {
        let target = rules.match_ip(&dst_ip).clone();
        if matches!(target, Target::Reject) {
            debug!(
                "Dst IP {} not accepted by any IP rule (or matched reject rule) from {}: dropping connection",
                dst_ip, peer_addr
            );
            return;
        }
        (target, dst_ip.to_string())
    };

    debug!(
        "TPROXY TCP connection from {} -> {} ({}:{}): target={}",
        peer_addr, dst_ip, target_host, dst_port, target
    );

    match target {
        Target::Reject => {
            debug!(
                "Rejecting connection to {} ({}:{})",
                target_host, dst_ip, dst_port
            );
        }
        Target::Direct => {
            if is_fake {
                fakeip_manager.inc_conn(&dst_ip);
            }
            if let Err(e) = handle_direct(stream, &target_host, dst_port, egress_mark).await {
                debug!(
                    "Direct outbound error for {}:{}: {}",
                    target_host, dst_port, e
                );
            }
            if is_fake {
                fakeip_manager.dec_conn(&dst_ip);
            }
        }
        Target::Http(proxy) => {
            if is_fake {
                fakeip_manager.inc_conn(&dst_ip);
            }
            if let Err(e) =
                handle_http_proxy(stream, &proxy, &target_host, dst_port, egress_mark).await
            {
                debug!(
                    "HTTP proxy outbound error for {}:{}: {}",
                    target_host, dst_port, e
                );
            }
            if is_fake {
                fakeip_manager.dec_conn(&dst_ip);
            }
        }
        Target::Socks5 { addr: proxy, .. } => {
            if is_fake {
                fakeip_manager.inc_conn(&dst_ip);
            }
            if let Err(e) =
                handle_socks5_proxy(stream, &proxy, &target_host, dst_port, egress_mark).await
            {
                debug!(
                    "SOCKS5 proxy outbound error for {}:{}: {}",
                    target_host, dst_port, e
                );
            }
            if is_fake {
                fakeip_manager.dec_conn(&dst_ip);
            }
        }
    }
}

async fn run_direct_udp_session(
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    reply_socket: Arc<UdpSocket>,
    outbound_socket: Arc<UdpSocket>,
) {
    let mut recv_buf = vec![0u8; 65535];
    let sleep = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            Some(data) = rx.recv() => {
                if outbound_socket.send(&data).await.is_err() {
                    break;
                }
                sleep.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(60));
            }
            res = outbound_socket.recv(&mut recv_buf) => {
                match res {
                    Ok(n) if n > 0 => {
                        let _ = reply_socket.send(&recv_buf[..n]).await;
                        sleep.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(60));
                    }
                    _ => break,
                }
            }
            () = &mut sleep => {
                break;
            }
        }
    }
}

async fn run_socks5_udp_session(
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    reply_socket: Arc<UdpSocket>,
    proxy_addr: String,
    target_host: String,
    target_port: u16,
    egress_mark: Option<u32>,
) {
    let assoc = match socks5_udp_associate(&proxy_addr, egress_mark).await {
        Ok(a) => a,
        Err(e) => {
            debug!(
                "Failed to establish SOCKS5 UDP ASSOCIATE with {}: {}",
                proxy_addr, e
            );
            return;
        }
    };

    let outbound_socket = match create_direct_outbound_socket(assoc.relay_addr, egress_mark) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            debug!(
                "Failed to connect to SOCKS5 relay endpoint {}: {}",
                assoc.relay_addr, e
            );
            return;
        }
    };

    let _tcp_stream = assoc.tcp_stream;
    let mut recv_buf = vec![0u8; 65535];
    let sleep = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            Some(payload) = rx.recv() => {
                if let Ok(packet) = encode_socks5_udp_packet(&target_host, target_port, &payload) {
                    if outbound_socket.send(&packet).await.is_err() {
                        break;
                    }
                    sleep.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(60));
                }
            }
            res = outbound_socket.recv(&mut recv_buf) => {
                match res {
                    Ok(n) if n > 0 => {
                        if let Ok((data, _)) = decode_socks5_udp_packet(&recv_buf[..n]) {
                            let _ = reply_socket.send(data).await;
                            sleep.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(60));
                        }
                    }
                    _ => break,
                }
            }
            () = &mut sleep => {
                break;
            }
        }
    }
}

fn create_transparent_reply_socket(
    orig_dst: SocketAddr,
    client_addr: SocketAddr,
    egress_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let domain = if orig_dst.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    let _ = socket.set_reuse_port(true);
    socket.set_nonblocking(true)?;

    if orig_dst.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }

    #[cfg(target_os = "linux")]
    {
        let fd = socket.as_raw_fd();
        let opt: libc::c_int = 1;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &opt as *const _ as *const libc::c_void,
                std::mem::size_of_val(&opt) as libc::socklen_t,
            );
            if orig_dst.is_ipv6() {
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_IPV6,
                    libc::IPV6_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
            }
        }
        if let Some(mark) = egress_mark {
            let val: libc::c_int = mark as libc::c_int;
            unsafe {
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                );
            }
        }
    }

    socket.bind(&orig_dst.into())?;
    socket.connect(&client_addr.into())?;
    UdpSocket::from_std(socket.into())
}

fn create_direct_outbound_socket(
    target_addr: SocketAddr,
    egress_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let domain = if target_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;

    #[cfg(target_os = "linux")]
    if let Some(mark) = egress_mark {
        let fd = socket.as_raw_fd();
        let val: libc::c_int = mark as libc::c_int;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
    }

    socket.connect(&target_addr.into())?;
    UdpSocket::from_std(socket.into())
}

#[cfg(target_os = "linux")]
pub fn recv_msg_with_orig_dst(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
    default_dst: SocketAddr,
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut control_buf = [0u8; 512];

    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msghdr.msg_namelen = std::mem::size_of_val(&src_storage) as libc::socklen_t;
    msghdr.msg_iov = &mut iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
    msghdr.msg_controllen = control_buf.len() as _;

    let ret = unsafe { libc::recvmsg(fd, &mut msghdr, libc::MSG_DONTWAIT) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = ret as usize;

    let peer_addr =
        sockaddr_to_socket_addr(&src_storage, msghdr.msg_namelen).unwrap_or(default_dst);

    let mut orig_dst = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msghdr);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let type_ = (*cmsg).cmsg_type;

            if level == libc::SOL_IP
                && (type_ == libc::IP_ORIGDSTADDR || type_ == libc::IP_RECVORIGDSTADDR)
            {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let sin = *data_ptr;
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                orig_dst = Some(SocketAddr::from((ip, port)));
                break;
            } else if level == libc::SOL_IPV6
                && (type_ == libc::IPV6_ORIGDSTADDR || type_ == libc::IPV6_RECVORIGDSTADDR)
            {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                let sin6 = *data_ptr;
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                orig_dst = Some(SocketAddr::from((ip, port)));
                break;
            }

            cmsg = libc::CMSG_NXTHDR(&msghdr, cmsg);
        }
    }

    Ok((n, peer_addr, orig_dst.unwrap_or(default_dst)))
}

#[cfg(not(target_os = "linux"))]
pub fn recv_msg_with_orig_dst(
    _fd: std::os::unix::io::RawFd,
    _buf: &mut [u8],
    default_dst: SocketAddr,
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TPROXY only supported on Linux",
    ))
}

fn sockaddr_to_socket_addr(
    storage: &libc::sockaddr_storage,
    _len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::from((ip, port)))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddr::from((ip, port)))
        }
        _ => None,
    }
}
