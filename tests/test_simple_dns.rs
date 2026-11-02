use simple_dns::{
    CLASS, Name, Packet, QCLASS, QTYPE, Question, ResourceRecord, TYPE,
    rdata::{A, RData},
};
use std::net::Ipv4Addr;

#[test]
fn test_dns_packet() {
    let mut packet = Packet::new_reply(1234);
    let question = Question::new(
        Name::new("example.com").unwrap(),
        QTYPE::TYPE(TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    );
    packet.questions.push(question);
    let record = ResourceRecord::new(
        Name::new("example.com").unwrap(),
        CLASS::IN,
        3,
        RData::A(A {
            address: Ipv4Addr::new(198, 18, 0, 2).into(),
        }),
    );
    packet.answers.push(record);
    let bytes = packet.build_bytes_vec_compressed().unwrap();
    let parsed = Packet::parse(&bytes).unwrap();
    assert_eq!(parsed.id(), 1234);
    assert_eq!(parsed.answers.len(), 1);
    if let RData::A(a) = &parsed.answers[0].rdata {
        let ip = Ipv4Addr::from(a.address);
        assert_eq!(ip, Ipv4Addr::new(198, 18, 0, 2));
    } else {
        panic!("expected A record");
    }
}
