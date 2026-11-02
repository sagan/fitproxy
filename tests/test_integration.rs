use ipnet::Ipv4Net;
use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE, rdata::RData};
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
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
    let range = Ipv4Net::from_str("198.18.0.0/24").unwrap();

    let mut static_fakeips = HashMap::new();
    let mut static_ip_to_domain = HashMap::new();
    let static_ip = Ipv4Addr::new(198, 18, 0, 50);
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
    let range = Ipv4Net::from_str("198.18.0.0/24").unwrap();

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
        let fake_ip = Ipv4Addr::from(a.address);
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

    // 4. AAAA query for allowed domain -> returns NODATA so client falls back to IPv4
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
