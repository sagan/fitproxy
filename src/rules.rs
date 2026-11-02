use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Http(String),
    Socks5(String),
    Direct,
    Reject,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Http(addr) => write!(f, "http://{}", addr),
            Target::Socks5(addr) => write!(f, "socks5://{}", addr),
            Target::Direct => write!(f, "direct"),
            Target::Reject => write!(f, "reject"),
        }
    }
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
pub struct Rule {
    pub pattern: DomainPattern,
    pub target: Target,
    pub raw: String,
}

impl Rule {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (domain_part, target_part) = if let Some((d, t)) = s.split_once('=') {
            (d.trim(), t.trim())
        } else if let Some((d, t)) = s.split_once('@') {
            (d.trim(), t.trim())
        } else {
            return Err(format!(
                "Invalid rule format (expected <domain>=<target>): '{}'",
                s
            ));
        };

        if domain_part.is_empty() {
            return Err(format!("Empty domain in rule: '{}'", s));
        }
        if target_part.is_empty() {
            return Err(format!("Empty target in rule: '{}'", s));
        }

        let pattern = DomainPattern::parse(domain_part);
        let target = if target_part.eq_ignore_ascii_case("direct") {
            Target::Direct
        } else if target_part.eq_ignore_ascii_case("reject") {
            Target::Reject
        } else if let Some(addr) = target_part.strip_prefix("socks5://") {
            Target::Socks5(addr.to_string())
        } else if let Some(addr) = target_part.strip_prefix("socks5h://") {
            Target::Socks5(addr.to_string())
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
        // README: "A implicit *@reject rule is always used as the last (fallback) rule."
        RuleSet {
            rules,
            fallback: Target::Reject,
        }
    }

    pub fn match_domain(&self, domain: &str) -> &Target {
        for rule in &self.rules {
            if rule.pattern.matches(domain) {
                return &rule.target;
            }
        }
        &self.fallback
    }

    pub fn is_allowed(&self, domain: &str) -> bool {
        !matches!(self.match_domain(domain), Target::Reject)
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
        assert_eq!(r2.target, Target::Socks5("127.0.0.1:1080".to_string()));

        let r3 = Rule::parse("google.com=socks5h://127.0.0.1:1080").unwrap();
        assert_eq!(r3.target, Target::Socks5("127.0.0.1:1080".to_string()));

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
}
