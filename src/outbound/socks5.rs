use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tracing::debug;

use crate::outbound::connect_tcp;

pub async fn handle_socks5_proxy(
    mut client_stream: TcpStream,
    proxy_addr: &str,
    target_host: &str,
    port: u16,
    egress_mark: Option<u32>,
) -> io::Result<()> {
    debug!(
        "Connecting to SOCKS5 proxy {} for {}:{}",
        proxy_addr, target_host, port
    );
    let mut proxy_stream = connect_tcp(proxy_addr, egress_mark).await?;

    // 1. Client Greeting: VER=5, NMETHODS=1, METHOD=0 (No Auth)
    proxy_stream.write_all(&[0x05, 0x01, 0x00]).await?;

    // 2. Server Choice
    let mut greeting_resp = [0u8; 2];
    proxy_stream.read_exact(&mut greeting_resp).await?;
    if greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("SOCKS5 proxy rejected authentication: {:?}", greeting_resp),
        ));
    }

    // 3. Connect request: VER=5, CMD=1 (CONNECT), RSV=0
    let mut request = Vec::with_capacity(32);
    request.push(0x05); // VER
    request.push(0x01); // CMD: CONNECT
    request.push(0x00); // RSV

    if let Ok(ip) = target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                request.push(0x01); // ATYP: IPv4
                request.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                request.push(0x04); // ATYP: IPv6
                request.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let domain_bytes = target_host.as_bytes();
        if domain_bytes.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Domain name too long for SOCKS5 (max 255 bytes)",
            ));
        }
        request.push(0x03); // ATYP: DOMAINNAME
        request.push(domain_bytes.len() as u8);
        request.extend_from_slice(domain_bytes);
    }
    request.extend_from_slice(&port.to_be_bytes());

    proxy_stream.write_all(&request).await?;

    // 4. Server Reply
    let mut reply_hdr = [0u8; 4];
    proxy_stream.read_exact(&mut reply_hdr).await?;
    if reply_hdr[0] != 0x05 || reply_hdr[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "SOCKS5 proxy connection failed with REP: {:#04x}",
                reply_hdr[1]
            ),
        ));
    }

    // Discard BND.ADDR and BND.PORT
    match reply_hdr[3] {
        0x01 => {
            // IPv4: 4 bytes IP + 2 bytes port
            let mut discard = [0u8; 6];
            proxy_stream.read_exact(&mut discard).await?;
        }
        0x03 => {
            // Domain: 1 byte len + len bytes domain + 2 bytes port
            let mut len = [0u8; 1];
            proxy_stream.read_exact(&mut len).await?;
            let mut discard = vec![0u8; len[0] as usize + 2];
            proxy_stream.read_exact(&mut discard).await?;
        }
        0x04 => {
            // IPv6: 16 bytes IP + 2 bytes port
            let mut discard = [0u8; 18];
            proxy_stream.read_exact(&mut discard).await?;
        }
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid SOCKS5 ATYP in reply: {:#04x}", atyp),
            ));
        }
    }

    debug!("SOCKS5 proxy handshake established for {}:{}", target_host, port);
    let _ = copy_bidirectional(&mut client_stream, &mut proxy_stream).await?;
    Ok(())
}
