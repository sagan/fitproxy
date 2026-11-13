use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tracing::debug;

use crate::outbound::{connect_tcp, format_authority};

pub async fn handle_http_proxy(
    mut client_stream: TcpStream,
    proxy_addr: &str,
    target_host: &str,
    port: u16,
    egress_mark: Option<u32>,
) -> io::Result<()> {
    debug!(
        "Connecting to HTTP proxy {} for {}:{}",
        proxy_addr, target_host, port
    );
    let mut proxy_stream = connect_tcp(proxy_addr, egress_mark).await?;

    let authority = format_authority(target_host, port);
    let connect_req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        authority, authority
    );
    proxy_stream.write_all(connect_req.as_bytes()).await?;

    // Read HTTP response header up to \r\n\r\n
    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if proxy_stream.read_exact(&mut temp).await.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "HTTP proxy closed connection during CONNECT handshake",
            ));
        }
        buf.push(temp[0]);
        if buf.len() > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP proxy response header too large",
            ));
        }
    }

    let resp_str = String::from_utf8_lossy(&buf);
    let status_line = resp_str.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") && !status_line.ends_with(" 200") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("HTTP proxy CONNECT rejected: {}", status_line),
        ));
    }

    debug!(
        "HTTP proxy handshake established for {}:{}",
        target_host, port
    );
    let _ = copy_bidirectional(&mut client_stream, &mut proxy_stream).await?;
    Ok(())
}
