use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tracing::debug;

use crate::outbound::connect_tcp;

pub struct Socks5UdpAssociation {
    pub tcp_stream: TcpStream,
    pub relay_addr: SocketAddr,
}

pub async fn socks5_udp_associate(
    proxy_addr: &str,
    egress_mark: Option<u32>,
) -> io::Result<Socks5UdpAssociation> {
    debug!("Starting SOCKS5 UDP ASSOCIATE with {}", proxy_addr);
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

    // 3. UDP ASSOCIATE Request: VER=5, CMD=3, RSV=0, ATYP=1, 0.0.0.0:0
    proxy_stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;

    // 4. Server Reply
    let mut reply_hdr = [0u8; 4];
    proxy_stream.read_exact(&mut reply_hdr).await?;
    if reply_hdr[0] != 0x05 || reply_hdr[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "SOCKS5 proxy UDP ASSOCIATE failed with REP: {:#04x}",
                reply_hdr[1]
            ),
        ));
    }

    let default_ip = proxy_stream.peer_addr()?.ip();

    let relay_addr = match reply_hdr[3] {
        0x01 => {
            // IPv4: 4 bytes IP + 2 bytes port
            let mut addr_buf = [0u8; 6];
            proxy_stream.read_exact(&mut addr_buf).await?;
            let ip = Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
            let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);
            if ip.is_unspecified() {
                SocketAddr::from((default_ip, port))
            } else {
                SocketAddr::from((IpAddr::V4(ip), port))
            }
        }
        0x03 => {
            // Domain: 1 byte len + len bytes domain + 2 bytes port
            let mut len_buf = [0u8; 1];
            proxy_stream.read_exact(&mut len_buf).await?;
            let mut domain_buf = vec![0u8; len_buf[0] as usize];
            proxy_stream.read_exact(&mut domain_buf).await?;
            let mut port_buf = [0u8; 2];
            proxy_stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let domain_str = String::from_utf8_lossy(&domain_buf);
            let host_port = format!("{}:{}", domain_str, port);
            tokio::net::lookup_host(&host_port)
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Failed to resolve SOCKS5 UDP relay host: {}", host_port),
                    )
                })?
        }
        0x04 => {
            // IPv6: 16 bytes IP + 2 bytes port
            let mut addr_buf = [0u8; 18];
            proxy_stream.read_exact(&mut addr_buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr_buf[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);
            if ip.is_unspecified() {
                SocketAddr::from((default_ip, port))
            } else {
                SocketAddr::from((IpAddr::V6(ip), port))
            }
        }
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid SOCKS5 ATYP in UDP ASSOCIATE reply: {:#04x}", atyp),
            ));
        }
    };

    debug!(
        "SOCKS5 UDP ASSOCIATE established with relay endpoint {}",
        relay_addr
    );
    Ok(Socks5UdpAssociation {
        tcp_stream: proxy_stream,
        relay_addr,
    })
}

pub fn encode_socks5_udp_packet(
    target_host: &str,
    port: u16,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(32 + payload.len());
    packet.push(0x00); // RSV
    packet.push(0x00); // RSV
    packet.push(0x00); // FRAG: 0 (standalone)

    if let Ok(ip) = target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                packet.push(0x01); // ATYP: IPv4
                request_extend_ip_v4(&mut packet, v4);
            }
            IpAddr::V6(v6) => {
                packet.push(0x04); // ATYP: IPv6
                packet.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let domain_bytes = target_host.as_bytes();
        if domain_bytes.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Domain name too long for SOCKS5 UDP header (max 255 bytes)",
            ));
        }
        packet.push(0x03); // ATYP: DOMAINNAME
        packet.push(domain_bytes.len() as u8);
        packet.extend_from_slice(domain_bytes);
    }
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn request_extend_ip_v4(buf: &mut Vec<u8>, v4: Ipv4Addr) {
    buf.extend_from_slice(&v4.octets());
}

pub fn decode_socks5_udp_packet(packet: &[u8]) -> io::Result<(&[u8], SocketAddr)> {
    if packet.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "SOCKS5 UDP packet too short",
        ));
    }
    let atyp = packet[3];
    let (header_len, remote_addr) = match atyp {
        0x01 => {
            if packet.len() < 10 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "SOCKS5 UDP IPv4 packet too short",
                ));
            }
            let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            (10, SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        0x04 => {
            if packet.len() < 22 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "SOCKS5 UDP IPv6 packet too short",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            (22, SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        0x03 => {
            let dlen = packet[4] as usize;
            let expected = 4 + 1 + dlen + 2;
            if packet.len() < expected {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "SOCKS5 UDP domain packet too short",
                ));
            }
            let port = u16::from_be_bytes([packet[5 + dlen], packet[6 + dlen]]);
            (expected, SocketAddr::from(([0, 0, 0, 0], port)))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown ATYP in SOCKS5 UDP packet: {:#04x}", atyp),
            ));
        }
    };

    Ok((&packet[header_len..], remote_addr))
}

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

    debug!(
        "SOCKS5 proxy handshake established for {}:{}",
        target_host, port
    );
    let _ = copy_bidirectional(&mut client_stream, &mut proxy_stream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_udp_packet_encode_decode_ipv4() {
        let payload = b"ping";
        let encoded = encode_socks5_udp_packet("1.2.3.4", 53, payload).unwrap();
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 0);
        assert_eq!(encoded[2], 0);
        assert_eq!(encoded[3], 1); // ATYP IPv4
        assert_eq!(&encoded[4..8], &[1, 2, 3, 4]);
        assert_eq!(&encoded[8..10], &53u16.to_be_bytes());
        assert_eq!(&encoded[10..], payload);

        let (decoded_payload, remote_addr) = decode_socks5_udp_packet(&encoded).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(remote_addr, "1.2.3.4:53".parse().unwrap());
    }

    #[test]
    fn test_socks5_udp_packet_encode_decode_ipv6() {
        let payload = b"ipv6 payload";
        let encoded = encode_socks5_udp_packet("2001:db8::1", 5353, payload).unwrap();
        assert_eq!(encoded[3], 4); // ATYP IPv6

        let (decoded_payload, remote_addr) = decode_socks5_udp_packet(&encoded).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(remote_addr, "[2001:db8::1]:5353".parse().unwrap());
    }

    #[test]
    fn test_socks5_udp_packet_encode_decode_domain() {
        let payload = b"domain payload";
        let encoded = encode_socks5_udp_packet("example.com", 1234, payload).unwrap();
        assert_eq!(encoded[3], 3); // ATYP domain
        assert_eq!(encoded[4], 11); // "example.com".len()

        let (decoded_payload, remote_addr) = decode_socks5_udp_packet(&encoded).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(remote_addr.port(), 1234);
    }
}
