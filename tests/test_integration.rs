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

    let rules = RuleSet::new(vec![
        Rule::parse("v6host.com=direct").unwrap(),
    ]);

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
    use fitproxy::config::{CliArgs, AppConfig};
    use clap::Parser;

    // 1. CLI parsing
    let cli = CliArgs::parse_from([
        "fitproxy",
        "--rule", "0.0.0.0/0=direct",
        "--interface", "eth0,eth1",
        "--egress-mark", "0x20000/0x20000",
        "--no-network-setup",
    ]);

    let config = AppConfig::load_and_merge(cli).expect("load config");
    assert_eq!(config.interfaces, vec!["eth0".to_string(), "eth1".to_string()]);
    assert_eq!(config.egress_mark.mark, 0x20000);
    assert_eq!(config.egress_mark.mask, Some(0x20000));
    assert_eq!(config.rules.allowed_ip_cidrs(), vec!["0.0.0.0/0".parse::<IpNet>().unwrap()]);

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
        "-c", config_file.to_str().unwrap(),
        "--no-network-setup",
    ]);
    let config2 = AppConfig::load_and_merge(cli2).expect("load config2");
    assert_eq!(config2.interfaces, vec!["ens33".to_string(), "wg0".to_string()]);
    assert_eq!(config2.egress_mark.mark, 0x10000);
    assert_eq!(config2.rules.allowed_ip_cidrs(), vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]);

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
    let allowed_cidrs = vec![
        "0.0.0.0/0".parse().unwrap(),
        "::/0".parse().unwrap(),
    ];

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

    // Verify script contains iifname clause and egress mark exclusion
    assert!(script.contains("meta mark and 0x10000 == 0x10000 accept"));
    assert!(script.contains("iifname { \"eth0\", \"eth1\" }"));

    // Verify syntax using `nft -c -f -`
    let mut child = Command::new("nft")
        .args(["-c", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nft -c");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().expect("wait nft -c");
    assert!(
        output.status.success(),
        "nft script syntax check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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

    assert_eq!(rules.match_ip(&echo_addr.ip()), &fitproxy::rules::Target::Direct);
    let reject_ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert_eq!(rules.match_ip(&reject_ip), &fitproxy::rules::Target::Reject);
    let unknown_ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert_eq!(rules.match_ip(&unknown_ip), &fitproxy::rules::Target::Reject);

    // Test handle_direct with egress_mark:
    // Create an in-memory client-server stream pair
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_port = client_listener.local_addr().unwrap().port();

    let client_connect_task = tokio::spawn(async move {
        let mut client_side = TcpStream::connect(("127.0.0.1", client_port)).await.unwrap();
        client_side.write_all(b"ping-pong").await.unwrap();
        let mut resp = [0u8; 9];
        client_side.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"ping-pong");
    });

    let (server_side, _) = client_listener.accept().await.unwrap();
    let direct_task = tokio::spawn(async move {
        handle_direct(server_side, &echo_addr.ip().to_string(), echo_addr.port(), Some(0x10000))
            .await
            .expect("handle_direct to echo server");
    });

    client_connect_task.await.unwrap();
    direct_task.await.unwrap();
}
