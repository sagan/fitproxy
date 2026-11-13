use ipnet::IpNet;
use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE, rdata::RData};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use fitproxy::cache::DiskCache;
use fitproxy::dns::DnsServer;
use fitproxy::fakeip::FakeIpManager;
use fitproxy::rules::{Rule, RuleSet};

#[test]
fn test_fakeip_allocation_and_static_priority() {
    let temp_dir = std::env::temp_dir().join("fitproxy_test_fakeip_alloc");
    let _ = fs::create_dir_all(&temp_dir);
    let cache_file = temp_dir.join("cache.jsonl");

    let disk_cache = Arc::new(DiskCache::new(cache_file));
    let range = IpNet::from_str("198.18.0.0/24").unwrap();

    let mut static_fakeips = HashMap::new();
    let mut static_ip_to_domain = HashMap::new();
    let static_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 50));
    static_fakeips.insert("static.com".to_string(), static_ip);
    static_ip_to_domain.insert(static_ip, "static.com".to_string());

    let mgr = FakeIpManager::new(
        range,
        static_fakeips,
        static_ip_to_domain,
        HashMap::new(),
        HashMap::new(),
        disk_cache,
    );

    // Static mapping must return pre-assigned IP
    let ip_static = mgr.lookup_or_allocate("static.com").unwrap();
    assert_eq!(ip_static, static_ip);
    assert_eq!(mgr.get_domain(&static_ip), Some("static.com".to_string()));

    // Dynamic mapping allocates a new IP in range
    let ip1 = mgr.lookup_or_allocate("dynamic1.org").unwrap();
    assert!(range.contains(&ip1));
    assert_ne!(ip1, static_ip);
    assert_eq!(mgr.get_domain(&ip1), Some("dynamic1.org".to_string()));

    // Repeated lookup for same domain returns same IP
    let ip1_repeat = mgr.lookup_or_allocate("dynamic1.org").unwrap();
    assert_eq!(ip1, ip1_repeat);

    // Another domain allocates distinct IP
    let ip2 = mgr.lookup_or_allocate("dynamic2.org").unwrap();
    assert_ne!(ip1, ip2);
    assert_ne!(ip2, static_ip);

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_dns_server_query_handling() {
    let temp_dir = std::env::temp_dir().join("fitproxy_test_dns_query");
    let _ = fs::create_dir_all(&temp_dir);
    let cache_file = temp_dir.join("cache.jsonl");

    let disk_cache = Arc::new(DiskCache::new(cache_file));
    let range = IpNet::from_str("198.18.0.0/24").unwrap();

    let mgr = FakeIpManager::new(
        range,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        disk_cache,
    );

    let rules = RuleSet::new(vec![
        Rule::parse("allowed.com=direct").unwrap(),
        Rule::parse("blocked.com=reject").unwrap(),
    ]);

    let dns_server = DnsServer::new("127.0.0.1:0".parse().unwrap(), mgr.clone(), rules);

    // 1. Query for allowed domain (A record)
    let mut req1 = Packet::new_query(1001);
    req1.questions.push(Question::new(
        Name::new("allowed.com").unwrap(),
        QTYPE::TYPE(TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let req1_bytes = req1.build_bytes_vec_compressed().unwrap();
    let resp1_bytes = dns_server.handle_query(&req1_bytes).expect("response");
    let resp1 = Packet::parse(&resp1_bytes).expect("parse response");

    assert_eq!(resp1.id(), 1001);
    assert_eq!(resp1.answers.len(), 1);
    if let RData::A(a) = &resp1.answers[0].rdata {
        let fake_ip = IpAddr::V4(Ipv4Addr::from(a.address));
        assert!(range.contains(&fake_ip));
        assert_eq!(mgr.get_domain(&fake_ip), Some("allowed.com".to_string()));
    } else {
        panic!("Expected A record");
    }

    // 2. Query for blocked domain (explicit reject rule)
    let mut req2 = Packet::new_query(1002);
    req2.questions.push(Question::new(
        Name::new("blocked.com").unwrap(),
        QTYPE::TYPE(TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let req2_bytes = req2.build_bytes_vec_compressed().unwrap();
    let resp2_bytes = dns_server.handle_query(&req2_bytes).expect("response");
    let resp2 = Packet::parse(&resp2_bytes).expect("parse response");

    assert_eq!(resp2.id(), 1002);
    assert_eq!(resp2.answers.len(), 0); // NODATA

    // 3. Query for unlisted domain (fallback reject)
    let mut req3 = Packet::new_query(1003);
    req3.questions.push(Question::new(
        Name::new("unlisted.xyz").unwrap(),
        QTYPE::TYPE(TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let req3_bytes = req3.build_bytes_vec_compressed().unwrap();
    let resp3_bytes = dns_server.handle_query(&req3_bytes).expect("response");
    let resp3 = Packet::parse(&resp3_bytes).expect("parse response");

    assert_eq!(resp3.answers.len(), 0); // NODATA

    // 4. AAAA query for allowed domain with IPv4 pool -> returns NODATA so client falls back to IPv4
    let mut req4 = Packet::new_query(1004);
    req4.questions.push(Question::new(
        Name::new("allowed.com").unwrap(),
        QTYPE::TYPE(TYPE::AAAA),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let req4_bytes = req4.build_bytes_vec_compressed().unwrap();
    let resp4_bytes = dns_server.handle_query(&req4_bytes).expect("response");
    let resp4 = Packet::parse(&resp4_bytes).expect("parse response");

    assert_eq!(resp4.answers.len(), 0); // NODATA for AAAA

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_dns_server_ipv6_query_handling() {
    let temp_dir = std::env::temp_dir().join("fitproxy_test_dns_v6_query");
    let _ = fs::create_dir_all(&temp_dir);
    let cache_file = temp_dir.join("cache.jsonl");

    let disk_cache = Arc::new(DiskCache::new(cache_file));
    let range = IpNet::from_str("fc00::/18").unwrap();

    let mgr = FakeIpManager::new(
        range,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        disk_cache,
    );

    let rules = RuleSet::new(vec![Rule::parse("v6host.com=direct").unwrap()]);

    let dns_server = DnsServer::new("127.0.0.1:0".parse().unwrap(), mgr.clone(), rules);

    // 1. Query for AAAA on IPv6 pool -> returns fake IPv6
    let mut req1 = Packet::new_query(2001);
    req1.questions.push(Question::new(
        Name::new("v6host.com").unwrap(),
        QTYPE::TYPE(TYPE::AAAA),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let req1_bytes = req1.build_bytes_vec_compressed().unwrap();
    let resp1_bytes = dns_server.handle_query(&req1_bytes).expect("response");
    let resp1 = Packet::parse(&resp1_bytes).expect("parse response");

    assert_eq!(resp1.id(), 2001);
    assert_eq!(resp1.answers.len(), 1);
    if let RData::AAAA(aaaa) = &resp1.answers[0].rdata {
        let fake_ip = IpAddr::V6(Ipv6Addr::from(aaaa.address));
        assert!(range.contains(&fake_ip));
        assert_eq!(mgr.get_domain(&fake_ip), Some("v6host.com".to_string()));
    } else {
        panic!("Expected AAAA record");
    }

    // 2. Query for A on IPv6 pool -> returns NODATA
    let mut req2 = Packet::new_query(2002);
    req2.questions.push(Question::new(
        Name::new("v6host.com").unwrap(),
        QTYPE::TYPE(TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let req2_bytes = req2.build_bytes_vec_compressed().unwrap();
    let resp2_bytes = dns_server.handle_query(&req2_bytes).expect("response");
    let resp2 = Packet::parse(&resp2_bytes).expect("parse response");

    assert_eq!(resp2.answers.len(), 0); // NODATA for A

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_config_interface_and_egress_mark_parsing() {
    use clap::Parser;
    use fitproxy::config::{AppConfig, CliArgs};

    // 1. CLI parsing
    let cli = CliArgs::parse_from([
        "fitproxy",
        "--rule",
        "0.0.0.0/0=direct",
        "--interface",
        "eth0,eth1",
        "--egress-mark",
        "0x20000/0x20000",
        "--no-network-setup",
    ]);

    let config = AppConfig::load_and_merge(cli).expect("load config");
    assert_eq!(
        config.interfaces,
        vec!["eth0".to_string(), "eth1".to_string()]
    );
    assert_eq!(config.egress_mark.mark, 0x20000);
    assert_eq!(config.egress_mark.mask, Some(0x20000));
    assert_eq!(
        config.rules.allowed_ip_cidrs(),
        vec!["0.0.0.0/0".parse::<IpNet>().unwrap()]
    );

    // 2. Config file parsing
    let temp_dir = std::env::temp_dir().join("fitproxy_test_config_json");
    let _ = fs::create_dir_all(&temp_dir);
    let config_file = temp_dir.join("fitproxy.json");

    let json_content = r#"{
        "rules": ["10.0.0.0/8=direct", "192.168.0.0/16=reject"],
        "interface": ["ens33", "wg0"],
        "egress_mark": "0x10000/0x10000"
    }"#;
    fs::write(&config_file, json_content).unwrap();

    let cli2 = CliArgs::parse_from([
        "fitproxy",
        "-c",
        config_file.to_str().unwrap(),
        "--no-network-setup",
    ]);
    let config2 = AppConfig::load_and_merge(cli2).expect("load config2");
    assert_eq!(
        config2.interfaces,
        vec!["ens33".to_string(), "wg0".to_string()]
    );
    assert_eq!(config2.egress_mark.mark, 0x10000);
    assert_eq!(
        config2.rules.allowed_ip_cidrs(),
        vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]
    );

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_nft_rules_syntax_validation() {
    use fitproxy::config::FwMark;
    use fitproxy::network::NetworkManager;
    use std::io::Write;
    use std::process::{Command, Stdio};

    let fakeip = "198.18.0.0/15".parse().unwrap();
    let fwmark = FwMark::parse("0x8000/0x8000").unwrap();
    let egress_mark = FwMark::parse("0x10000/0x10000").unwrap();
    let allowed_cidrs = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];

    let nm = NetworkManager::new(
        fakeip,
        allowed_cidrs,
        7080,
        7080,
        fwmark,
        egress_mark,
        vec!["eth0".to_string(), "eth1".to_string()],
    );

    let script = nm.generate_nft_script();

    // Verify script contains iifname clause, daddr sets, protocols, and egress mark exclusion
    assert!(script.contains("meta mark and 0x10000 == 0x10000 accept"));
    assert!(script.contains("iifname { \"eth0\", \"eth1\" }"));
    assert!(script.contains("fib daddr type != local ip daddr { 198.18.0.0/15, 0.0.0.0/0 }"));
    assert!(script.contains("fib daddr type != local ip6 daddr { ::/0 }"));
    assert!(script.contains("meta l4proto { tcp, udp }"));

    // Verify syntax using `nft -c -f -` if available and permitted
    let mut child = match Command::new("nft")
        .args(["-c", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "nft command not available ({}), skipping nft syntax check",
                e
            );
            return;
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes());
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to wait for nft: {}, skipping", e);
            return;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // In unprivileged test environments (e.g. GitHub Actions CI runners), nft -c fails
        // netlink cache initialization with "Operation not permitted" due to lack of CAP_NET_ADMIN.
        if stderr.contains("Operation not permitted")
            || stderr.contains("cache initialization failed")
            || stderr.contains("Permission denied")
        {
            eprintln!(
                "Skipping nft syntax validation: environment lacks netlink permissions ({})",
                stderr.trim()
            );
            return;
        }
        panic!("nft script syntax check failed: {}", stderr);
    }
}

#[tokio::test]
async fn test_tproxy_server_direct_ip_forwarding() {
    use fitproxy::outbound::handle_direct;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // Start a real target TCP echo server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 128];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    // Configure RuleSet with IP rules:
    // 127.0.0.1/32=direct
    // 192.168.0.0/16=reject
    let rules = RuleSet::new(vec![
        Rule::parse("127.0.0.1/32=direct").unwrap(),
        Rule::parse("192.168.0.0/16=reject").unwrap(),
    ]);

    assert_eq!(
        rules.match_ip(&echo_addr.ip()),
        &fitproxy::rules::Target::Direct
    );
    let reject_ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert_eq!(rules.match_ip(&reject_ip), &fitproxy::rules::Target::Reject);
    let unknown_ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert_eq!(
        rules.match_ip(&unknown_ip),
        &fitproxy::rules::Target::Reject
    );

    // Test handle_direct with egress_mark:
    // Create an in-memory client-server stream pair
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_port = client_listener.local_addr().unwrap().port();

    let client_connect_task = tokio::spawn(async move {
        let mut client_side = TcpStream::connect(("127.0.0.1", client_port))
            .await
            .unwrap();
        client_side.write_all(b"ping-pong").await.unwrap();
        let mut resp = [0u8; 9];
        client_side.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"ping-pong");
    });

    let (server_side, _) = client_listener.accept().await.unwrap();
    let direct_task = tokio::spawn(async move {
        handle_direct(
            server_side,
            &echo_addr.ip().to_string(),
            echo_addr.port(),
            Some(0x10000),
        )
        .await
        .expect("handle_direct to echo server");
    });

    client_connect_task.await.unwrap();
    direct_task.await.unwrap();
}

#[tokio::test]
async fn test_socks5_udp_parameter_and_rules() {
    let r1 = Rule::parse("domain.com=socks5://127.0.0.1:1080?udp=0").unwrap();
    assert_eq!(
        r1.target,
        fitproxy::rules::Target::Socks5 {
            addr: "127.0.0.1:1080".to_string(),
            udp: false,
        }
    );

    let r2 = Rule::parse("domain.com=socks5://127.0.0.1:1080?udp=false").unwrap();
    assert_eq!(
        r2.target,
        fitproxy::rules::Target::Socks5 {
            addr: "127.0.0.1:1080".to_string(),
            udp: false,
        }
    );

    let r3 = Rule::parse("domain.com=socks5://127.0.0.1:1080?udp=1").unwrap();
    assert_eq!(
        r3.target,
        fitproxy::rules::Target::Socks5 {
            addr: "127.0.0.1:1080".to_string(),
            udp: true,
        }
    );

    let r4 = Rule::parse("domain.com=socks5://127.0.0.1:1080").unwrap();
    assert_eq!(
        r4.target,
        fitproxy::rules::Target::Socks5 {
            addr: "127.0.0.1:1080".to_string(),
            udp: true,
        }
    );
}

#[tokio::test]
async fn test_socks5_udp_associate_protocol() {
    use fitproxy::outbound::{
        decode_socks5_udp_packet, encode_socks5_udp_packet, socks5_udp_associate,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    // 1. Start a mock UDP relay endpoint
    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        if let Ok((n, src)) = relay_socket.recv_from(&mut buf).await {
            // Echo back with SOCKS5 UDP header
            let (payload, _target) = decode_socks5_udp_packet(&buf[..n]).unwrap();
            let reply_packet = encode_socks5_udp_packet("127.0.0.1", 53, payload).unwrap();
            let _ = relay_socket.send_to(&reply_packet, src).await;
        }
    });

    // 2. Start a mock SOCKS5 server handling TCP handshake and UDP ASSOCIATE
    let socks5_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks5_addr = socks5_listener.local_addr().unwrap();

    let relay_port = relay_addr.port();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = socks5_listener.accept().await {
            // Read greeting: [0x05, 0x01, 0x00]
            let mut greet = [0u8; 3];
            stream.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet[0], 0x05);
            // Send choice: [0x05, 0x00]
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            // Read UDP ASSOCIATE request: [0x05, 0x03, 0x00, 0x01, ...]
            let mut req = [0u8; 10];
            stream.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0x05);
            assert_eq!(req[1], 0x03); // CMD: UDP ASSOCIATE

            // Send reply: VER=5, REP=0, RSV=0, ATYP=1, IP=127.0.0.1, PORT=relay_port
            let mut rep = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
            rep.extend_from_slice(&relay_port.to_be_bytes());
            stream.write_all(&rep).await.unwrap();

            // Keep TCP connection open while testing
            let mut dummy = [0u8; 1];
            let _ = stream.read(&mut dummy).await;
        }
    });

    // 3. Test socks5_udp_associate client
    let assoc = socks5_udp_associate(&socks5_addr.to_string(), None)
        .await
        .expect("socks5 udp associate");
    assert_eq!(assoc.relay_addr, relay_addr);

    // 4. Send UDP packet to relay endpoint
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_udp.connect(assoc.relay_addr).await.unwrap();

    let payload = b"socks5-udp-test";
    let encoded = encode_socks5_udp_packet("8.8.8.8", 53, payload).unwrap();
    client_udp.send(&encoded).await.unwrap();

    let mut resp_buf = [0u8; 512];
    let n = client_udp.recv(&mut resp_buf).await.unwrap();
    let (decoded_payload, target) = decode_socks5_udp_packet(&resp_buf[..n]).unwrap();
    assert_eq!(decoded_payload, payload);
    assert_eq!(target, "127.0.0.1:53".parse().unwrap());
}
