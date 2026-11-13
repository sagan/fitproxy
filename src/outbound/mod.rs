use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use tokio::net::TcpStream;
use tracing::debug;

pub mod direct;
pub mod http;
pub mod socks5;

pub use direct::handle_direct;
pub use http::handle_http_proxy;
pub use socks5::{
    Socks5UdpAssociation, decode_socks5_udp_packet, encode_socks5_udp_packet, handle_socks5_proxy,
    socks5_udp_associate,
};

pub fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

pub async fn connect_host(
    host: &str,
    port: u16,
    egress_mark: Option<u32>,
) -> io::Result<TcpStream> {
    let authority = format_authority(host, port);
    connect_tcp(&authority, egress_mark).await
}

pub async fn connect_tcp(target: &str, egress_mark: Option<u32>) -> io::Result<TcpStream> {
    let addrs = tokio::net::lookup_host(target).await?;
    let mut last_err = None;

    for addr in addrs {
        let socket = if addr.is_ipv6() {
            tokio::net::TcpSocket::new_v6()?
        } else {
            tokio::net::TcpSocket::new_v4()?
        };

        #[cfg(target_os = "linux")]
        if let Some(mark) = egress_mark {
            let fd = socket.as_raw_fd();
            let val: libc::c_int = mark as libc::c_int;
            unsafe {
                let ret = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                );
                if ret != 0 {
                    let err = io::Error::last_os_error();
                    debug!(
                        "Failed to set SO_MARK 0x{:x} on egress socket: {}",
                        mark, err
                    );
                } else {
                    debug!("Set SO_MARK 0x{:x} on egress socket", mark);
                }
            }
        }

        match socket.connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("Unable to connect to: {}", target),
        )
    }))
}
