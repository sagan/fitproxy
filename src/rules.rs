use ipnet::IpNet;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Http(String),
    Socks5 { addr: String, udp: bool },
    Direct,
    Reject,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Http(addr) => write!(f, "http://{}", addr),
            Target::Socks5 { addr, udp } => {
                if *udp {
                    write!(f, "socks5://{}", addr)
                } else {
                    write!(f, "socks5://{}?udp=0", addr)
                }
            }
            Target::Direct => write!(f, "direct"),
            Target::Reject => write!(f, "reject"),
        }
    }
}

pub fn parse_socks5_target_part(rest: &str) -> (String, bool) {
    let mut udp = true;
    let addr = if let Some((addr_part, query_part)) = rest.split_once('?') {
        for query_item in query_part.split('&') {
            if let Some((k, v)) = query_item.split_once('=') {
                if k.trim().eq_ignore_ascii_case("udp") {
                    let v = v.trim().to_ascii_lowercase();
                    if v == "0" || v == "false" || v == "no" || v == "off" {
                        udp = false;
                    } else if v == "1" || v == "true" || v == "yes" || v == "on" {
                        udp = true;
                    }
                }
            }
        }
        addr_part.trim().to_string()
    } else {
        rest.trim().to_string()
    };
    (addr, udp)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    /// Matches subdomains only, e.g. *.example.com matches a.example.com but not example.com
    WildcardSubdomains(String),
    /// Matches exact domain only, e.g. -.example.com matches example.com only
    ExactOnly(String),
    /// Matches domain and all subdomains, e.g. example.com matches example.com and a.example.com
    SubdomainsAndExact(String),
    /// Catch-all (e.g. *)
    CatchAll,
}

impl DomainPattern {
    pub fn parse(s: &str) -> Self {
        let s = s.trim().to_ascii_lowercase();
        let s = s.trim_end_matches('.');
        if s == "*" {
            DomainPattern::CatchAll
        } else if let Some(rest) = s.strip_prefix("*.") {
            DomainPattern::WildcardSubdomains(rest.to_string())
        } else if let Some(rest) = s.strip_prefix("-.") {
            DomainPattern::ExactOnly(rest.to_string())
        } else {
            DomainPattern::SubdomainsAndExact(s.to_string())
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim().to_ascii_lowercase();
        let domain = domain.trim_end_matches('.');

        match self {
            DomainPattern::CatchAll => true,
            DomainPattern::ExactOnly(base) => domain == base,
            DomainPattern::WildcardSubdomains(base) => {
                if domain == base {
                    false
                } else {
                    domain.ends_with(base) && domain[..domain.len() - base.len()].ends_with('.')
                }
            }
            DomainPattern::SubdomainsAndExact(base) => {
                if domain == base {
                    true
                } else {
                    domain.ends_with(base) && domain[..domain.len() - base.len()].ends_with('.')
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulePattern {
    Domain(DomainPattern),
    Ip(IpNet),
}

impl RulePattern {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.contains('/') {
            let net = s
                .parse::<IpNet>()
                .map_err(|e| format!("Invalid IP CIDR in rule pattern '{}': {}", s, e))?;
            Ok(RulePattern::Ip(net))
        } else if let Ok(ip) = s.parse::<IpAddr>() {
            Ok(RulePattern::Ip(IpNet::from(ip)))
        } else {
            Ok(RulePattern::Domain(DomainPattern::parse(s)))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub pattern: RulePattern,
    pub target: Target,
    pub raw: String,
}

impl Rule {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (pattern_part, target_part) = if let Some((d, t)) = s.split_once('=') {
            (d.trim(), t.trim())
        } else if let Some((d, t)) = s.split_once('@') {
            (d.trim(), t.trim())
        } else {
            return Err(format!(
                "Invalid rule format (expected <pattern>=<target>): '{}'",
                s
            ));
        };

        if pattern_part.is_empty() {
            return Err(format!("Empty pattern in rule: '{}'", s));
        }
        if target_part.is_empty() {
            return Err(format!("Empty target in rule: '{}'", s));
        }

        let pattern = RulePattern::parse(pattern_part)?;
        let target = if target_part.eq_ignore_ascii_case("direct") {
            Target::Direct
        } else if target_part.eq_ignore_ascii_case("reject") {
            Target::Reject
        } else if let Some(rest) = target_part
            .strip_prefix("socks5://")
            .or_else(|| target_part.strip_prefix("socks5h://"))
        {
            let (addr, udp) = parse_socks5_target_part(rest);
            Target::Socks5 { addr, udp }
        } else if let Some(addr) = target_part.strip_prefix("http://") {
            Target::Http(addr.to_string())
        } else {
            // Implicit HTTP proxy
            Target::Http(target_part.to_string())
        };

        Ok(Rule {
            pattern,
            target,
            raw: s.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<Rule>,
    fallback: Target,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Self {
        // README: "A implicit *=reject rule is always used as the last (fallback) rule."
        RuleSet {
            rules,
            fallback: Target::Reject,
        }
    }

    pub fn match_domain(&self, domain: &str) -> &Target {
        for rule in &self.rules {
            if let RulePattern::Domain(ref pat) = rule.pattern {
                if pat.matches(domain) {
                    return &rule.target;
                }
            }
        }
        &self.fallback
    }

    pub fn match_ip(&self, ip: &IpAddr) -> &Target {
        let ip = ip.to_canonical();
        let mut best_match: Option<(&Target, u8)> = None;

        for rule in &self.rules {
            if let RulePattern::Ip(ref net) = rule.pattern {
                if net.contains(&ip) {
                    let prefix_len = net.prefix_len();
                    match best_match {
                        Some((_, best_len)) if prefix_len > best_len => {
                            best_match = Some((&rule.target, prefix_len));
                        }
                        None => {
                            best_match = Some((&rule.target, prefix_len));
                        }
                        _ => {}
                    }
                }
            }
        }

        if let Some((target, _)) = best_match {
            target
        } else {
            &self.fallback
        }
    }

    pub fn is_allowed(&self, domain: &str) -> bool {
        !matches!(self.match_domain(domain), Target::Reject)
    }

    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        !matches!(self.match_ip(ip), Target::Reject)
    }

    pub fn allowed_ip_cidrs(&self) -> Vec<IpNet> {
        let mut cidrs = Vec::new();
        for rule in &self.rules {
            if let RulePattern::Ip(ref net) = rule.pattern {
                if !matches!(rule.target, Target::Reject) && !cidrs.contains(net) {
                    cidrs.push(*net);
                }
            }
        }
        cidrs
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_pattern_default() {
        let p = DomainPattern::parse("example.com");
        assert!(p.matches("example.com"));
        assert!(p.matches("a.example.com"));
        assert!(p.matches("a.b.example.com"));
        assert!(!p.matches("notexample.com"));
        assert!(!p.matches("com"));
    }

    #[test]
    fn test_domain_pattern_wildcard() {
        let p = DomainPattern::parse("*.example.com");
        assert!(!p.matches("example.com"));
        assert!(p.matches("a.example.com"));
        assert!(p.matches("b.a.example.com"));
        assert!(!p.matches("other.com"));
    }

    #[test]
    fn test_domain_pattern_exact() {
        let p = DomainPattern::parse("-.example.com");
        assert!(p.matches("example.com"));
        assert!(!p.matches("a.example.com"));
        assert!(!p.matches("b.a.example.com"));
    }

    #[test]
    fn test_rule_parsing() {
        let r1 = Rule::parse("example.com=127.0.0.1:1080").unwrap();
        assert_eq!(r1.target, Target::Http("127.0.0.1:1080".to_string()));

        let r2 = Rule::parse("ipinfo.io=socks5://127.0.0.1:1080").unwrap();
        assert_eq!(
            r2.target,
            Target::Socks5 {
                addr: "127.0.0.1:1080".to_string(),
                udp: true,
            }
        );

        let r3 = Rule::parse("google.com=socks5h://127.0.0.1:1080").unwrap();
        assert_eq!(
            r3.target,
            Target::Socks5 {
                addr: "127.0.0.1:1080".to_string(),
                udp: true,
            }
        );

        let r3_no_udp = Rule::parse("google.com=socks5://127.0.0.1:1080?udp=0").unwrap();
        assert_eq!(
            r3_no_udp.target,
            Target::Socks5 {
                addr: "127.0.0.1:1080".to_string(),
                udp: false,
            }
        );

        let r4 = Rule::parse("local.net=direct").unwrap();
        assert_eq!(r4.target, Target::Direct);

        let r5 = Rule::parse("bad.com=reject").unwrap();
        assert_eq!(r5.target, Target::Reject);

        // Also verify backward compatible @ syntax
        let r_compat = Rule::parse("compat.com@127.0.0.1:1080").unwrap();
        assert_eq!(r_compat.target, Target::Http("127.0.0.1:1080".to_string()));
    }

    #[test]
    fn test_ruleset_precedence_and_fallback() {
        let r1 = Rule::parse("-.foo.com=direct").unwrap();
        let r2 = Rule::parse("foo.com=reject").unwrap();
        let r3 = Rule::parse("*.bar.com=127.0.0.1:8080").unwrap();

        let set = RuleSet::new(vec![r1, r2, r3]);

        assert_eq!(set.match_domain("foo.com"), &Target::Direct);
        assert_eq!(set.match_domain("sub.foo.com"), &Target::Reject);
        assert_eq!(
            set.match_domain("sub.bar.com"),
            &Target::Http("127.0.0.1:8080".to_string())
        );
        assert_eq!(set.match_domain("bar.com"), &Target::Reject); // fallback
        assert_eq!(set.match_domain("unknown.org"), &Target::Reject); // fallback
    }

    #[test]
    fn test_ip_rule_parsing() {
        let r1 = Rule::parse("0.0.0.0/0=direct").unwrap();
        assert_eq!(r1.target, Target::Direct);
        assert_eq!(
            r1.pattern,
            RulePattern::Ip("0.0.0.0/0".parse::<IpNet>().unwrap())
        );

        let r2 = Rule::parse("192.168.1.0/24=reject").unwrap();
        assert_eq!(r2.target, Target::Reject);
        assert_eq!(
            r2.pattern,
            RulePattern::Ip("192.168.1.0/24".parse::<IpNet>().unwrap())
        );

        let r3 = Rule::parse("10.0.0.1=127.0.0.1:8080").unwrap();
        assert_eq!(r3.target, Target::Http("127.0.0.1:8080".to_string()));
        assert_eq!(
            r3.pattern,
            RulePattern::Ip("10.0.0.1/32".parse::<IpNet>().unwrap())
        );

        let r4 = Rule::parse("::/0=socks5://127.0.0.1:1080").unwrap();
        assert_eq!(
            r4.target,
            Target::Socks5 {
                addr: "127.0.0.1:1080".to_string(),
                udp: true,
            }
        );
        assert_eq!(
            r4.pattern,
            RulePattern::Ip("::/0".parse::<IpNet>().unwrap())
        );

        let r5 = Rule::parse("2001:db8::/32=direct").unwrap();
        assert_eq!(r5.target, Target::Direct);
        assert_eq!(
            r5.pattern,
            RulePattern::Ip("2001:db8::/32".parse::<IpNet>().unwrap())
        );

        // Invalid CIDR should error
        assert!(Rule::parse("999.999.999.999/24=direct").is_err());
        assert!(Rule::parse("1.2.3.4/40=direct").is_err());
    }

    #[test]
    fn test_ip_ruleset_matching_and_lpm() {
        // More specific prefix wins:
        // 192.168.1.100/32 -> direct
        // 192.168.0.0/16 -> reject
        // 0.0.0.0/0 -> direct
        let r1 = Rule::parse("0.0.0.0/0=direct").unwrap();
        let r2 = Rule::parse("192.168.0.0/16=reject").unwrap();
        let r3 = Rule::parse("192.168.1.100=direct").unwrap();
        let r4 = Rule::parse("::/0=socks5://127.0.0.1:1080").unwrap();
        let r5 = Rule::parse("fc00::/7=reject").unwrap();

        let set = RuleSet::new(vec![r1, r2, r3, r4, r5]);

        let ip_host: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(set.match_ip(&ip_host), &Target::Direct);

        let ip_subnet: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(set.match_ip(&ip_subnet), &Target::Reject);

        let ip_public: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(set.match_ip(&ip_public), &Target::Direct);

        let ip_v6_ula: IpAddr = "fd00::1".parse().unwrap();
        assert_eq!(set.match_ip(&ip_v6_ula), &Target::Reject);

        let ip_v6_public: IpAddr = "2606:4700::6810".parse().unwrap();
        assert_eq!(
            set.match_ip(&ip_v6_public),
            &Target::Socks5 {
                addr: "127.0.0.1:1080".to_string(),
                udp: true,
            }
        );

        // IPv4-mapped IPv6 address should match IPv4 rule
        let ip_mapped: IpAddr = "::ffff:192.168.1.100".parse().unwrap();
        assert_eq!(set.match_ip(&ip_mapped), &Target::Direct);

        let ip_mapped_reject: IpAddr = "::ffff:192.168.1.50".parse().unwrap();
        assert_eq!(set.match_ip(&ip_mapped_reject), &Target::Reject);
    }

    #[test]
    fn test_ip_ruleset_allowed_cidrs() {
        let r1 = Rule::parse("0.0.0.0/0=direct").unwrap();
        let r2 = Rule::parse("10.0.0.0/8=127.0.0.1:8080").unwrap();
        let r3 = Rule::parse("192.168.0.0/16=reject").unwrap();
        let r4 = Rule::parse("::/0=direct").unwrap();
        let r5 = Rule::parse("domain.com=direct").unwrap();

        let set = RuleSet::new(vec![r1, r2, r3, r4, r5]);
        let cidrs = set.allowed_ip_cidrs();

        assert_eq!(cidrs.len(), 3);
        assert!(cidrs.contains(&"0.0.0.0/0".parse().unwrap()));
        assert!(cidrs.contains(&"10.0.0.0/8".parse().unwrap()));
        assert!(cidrs.contains(&"::/0".parse().unwrap()));
        assert!(!cidrs.contains(&"192.168.0.0/16".parse().unwrap()));
    }
}
