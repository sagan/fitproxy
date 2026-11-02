use simple_dns::{
    CLASS, Packet, QTYPE, ResourceRecord, TYPE,
    rdata::{A, AAAA, RData},
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::fakeip::FakeIpManager;
use crate::rules::RuleSet;

pub struct DnsServer {
    listen_addr: SocketAddr,
    fakeip_manager: FakeIpManager,
    rules: RuleSet,
}

impl DnsServer {
    pub fn new(listen_addr: SocketAddr, fakeip_manager: FakeIpManager, rules: RuleSet) -> Self {
        DnsServer {
            listen_addr,
            fakeip_manager,
            rules,
        }
    }

    pub async fn run(self: Arc<Self>) -> std::io::Result<()> {
        let udp_socket = UdpSocket::bind(self.listen_addr).await?;
        let tcp_listener = TcpListener::bind(self.listen_addr).await?;
        info!("DNS server listening on UDP and TCP {}", self.listen_addr);

        let this_udp = self.clone();
        let udp_task = tokio::spawn(async move {
            this_udp.run_udp(udp_socket).await;
        });

        let this_tcp = self.clone();
        let tcp_task = tokio::spawn(async move {
            this_tcp.run_tcp(tcp_listener).await;
        });

        tokio::select! {
            res = udp_task => {
                if let Err(e) = res {
                    error!("DNS UDP task terminated: {}", e);
                }
            }
            res = tcp_task => {
                if let Err(e) = res {
                    error!("DNS TCP task terminated: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn run_udp(&self, socket: UdpSocket) {
        let mut buf = vec![0u8; 4096];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    let data = &buf[..len];
                    if let Some(resp_bytes) = self.handle_query(data) {
                        if let Err(e) = socket.send_to(&resp_bytes, peer).await {
                            warn!("Failed to send DNS UDP response to {}: {}", peer, e);
                        }
                    }
                }
                Err(e) => {
                    error!("DNS UDP recv error: {}", e);
                    break;
                }
            }
        }
    }

    async fn run_tcp(&self, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((mut stream, _peer)) => {
                    let this = self.clone_self();
                    tokio::spawn(async move {
                        let mut len_buf = [0u8; 2];
                        loop {
                            if stream.read_exact(&mut len_buf).await.is_err() {
                                break;
                            }
                            let msg_len = u16::from_be_bytes(len_buf) as usize;
                            if msg_len > 65535 || msg_len == 0 {
                                break;
                            }
                            let mut msg_buf = vec![0u8; msg_len];
                            if stream.read_exact(&mut msg_buf).await.is_err() {
                                break;
                            }

                            if let Some(resp_bytes) = this.handle_query(&msg_buf) {
                                let resp_len = resp_bytes.len() as u16;
                                if stream.write_all(&resp_len.to_be_bytes()).await.is_err() {
                                    break;
                                }
                                if stream.write_all(&resp_bytes).await.is_err() {
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("DNS TCP accept error: {}", e);
                    break;
                }
            }
        }
    }

    fn clone_self(&self) -> Arc<Self> {
        Arc::new(DnsServer {
            listen_addr: self.listen_addr,
            fakeip_manager: self.fakeip_manager.clone(),
            rules: self.rules.clone(),
        })
    }

    pub fn handle_query(&self, data: &[u8]) -> Option<Vec<u8>> {
        let req = match Packet::parse(data) {
            Ok(p) => p,
            Err(e) => {
                debug!("Failed to parse DNS query: {}", e);
                return None;
            }
        };

        let mut reply = Packet::new_reply(req.id());
        reply.questions = req.questions.clone();
        reply.set_flags(simple_dns::PacketFlag::RECURSION_AVAILABLE);

        for question in &req.questions {
            let qname = question.qname.to_string();
            let domain = qname.trim().trim_end_matches('.').to_ascii_lowercase();

            // Check if domain is allowed by proxy rules
            if !self.rules.is_allowed(&domain) {
                debug!("DNS query for '{}' rejected by rules", domain);
                // Return NODATA (NOERROR with 0 answer) so client fails immediately
                continue;
            }

            match question.qtype {
                QTYPE::TYPE(TYPE::A) => {
                    if let Some(fake_ip) = self.fakeip_manager.lookup_or_allocate(&domain) {
                        match fake_ip {
                            IpAddr::V4(v4) => {
                                debug!("DNS resolved '{}' (A) -> {}", domain, v4);
                                let record = ResourceRecord::new(
                                    question.qname.clone(),
                                    CLASS::IN,
                                    3, // 3-second TTL for fake IP
                                    RData::A(A {
                                        address: v4.into(),
                                    }),
                                );
                                reply.answers.push(record);
                            }
                            IpAddr::V6(_) => {
                                debug!("DNS A query for IPv6-pool domain '{}' -> NODATA", domain);
                            }
                        }
                    } else {
                        warn!("Failed to allocate fake IP for '{}'", domain);
                    }
                }
                QTYPE::TYPE(TYPE::AAAA) => {
                    if let Some(fake_ip) = self.fakeip_manager.lookup_or_allocate(&domain) {
                        match fake_ip {
                            IpAddr::V6(v6) => {
                                debug!("DNS resolved '{}' (AAAA) -> {}", domain, v6);
                                let record = ResourceRecord::new(
                                    question.qname.clone(),
                                    CLASS::IN,
                                    3, // 3-second TTL for fake IP
                                    RData::AAAA(AAAA {
                                        address: v6.into(),
                                    }),
                                );
                                reply.answers.push(record);
                            }
                            IpAddr::V4(_) => {
                                debug!("DNS AAAA query for IPv4-pool domain '{}' -> NODATA", domain);
                            }
                        }
                    } else {
                        warn!("Failed to allocate fake IP for '{}'", domain);
                    }
                }
                _ => {
                    // Other types (HTTPS, TXT, etc.): return empty answer
                    debug!(
                        "DNS query type {:?} for '{}' -> NODATA",
                        question.qtype, domain
                    );
                }
            }
        }

        match reply.build_bytes_vec_compressed() {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                warn!("Failed to build DNS response packet: {}", e);
                None
            }
        }
    }
}
