use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tracing::debug;

pub async fn handle_socks5_proxy(
    mut client_stream: TcpStream,
    proxy_addr: &str,
    domain: &str,
    port: u16,
) -> io::Result<()> {
    debug!(
        "Connecting to SOCKS5 proxy {} for {}:{}",
        proxy_addr, domain, port
    );
    let mut proxy_stream = TcpStream::connect(proxy_addr).await?;

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

    // 3. Connect request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (DOMAINNAME)
    let domain_bytes = domain.as_bytes();
    if domain_bytes.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Domain name too long for SOCKS5 (max 255 bytes)",
        ));
    }

    let mut request = Vec::with_capacity(7 + domain_bytes.len());
    request.push(0x05); // VER
    request.push(0x01); // CMD: CONNECT
    request.push(0x00); // RSV
    request.push(0x03); // ATYP: DOMAINNAME
    request.push(domain_bytes.len() as u8);
    request.extend_from_slice(domain_bytes);
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

    debug!("SOCKS5 proxy handshake established for {}:{}", domain, port);
    let _ = copy_bidirectional(&mut client_stream, &mut proxy_stream).await?;
    Ok(())
}
