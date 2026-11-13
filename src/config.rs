use clap::Parser;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::rules::{Rule, RuleSet};

pub fn parse_u32_hex_or_dec(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("Invalid hex number '{}': {}", s, e))
    } else {
        s.parse::<u32>().map_err(|e| format!("Invalid number '{}': {}", s, e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwMark {
    pub mark: u32,
    pub mask: Option<u32>,
    pub raw: String,
}

impl FwMark {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some((mark_str, mask_str)) = s.split_once('/') {
            let mark = parse_u32_hex_or_dec(mark_str)?;
            let mask = parse_u32_hex_or_dec(mask_str)?;
            Ok(FwMark {
                mark,
                mask: Some(mask),
                raw: s.to_string(),
            })
        } else {
            let mark = parse_u32_hex_or_dec(s)?;
            Ok(FwMark {
                mark,
                mask: None,
                raw: s.to_string(),
            })
        }
    }

    /// String formatted for `ip rule`: e.g. "0x8000/0x8000" or "0x8000"
    pub fn to_ip_rule_str(&self) -> String {
        if let Some(mask) = self.mask {
            format!("0x{:x}/0x{:x}", self.mark, mask)
        } else {
            format!("0x{:x}", self.mark)
        }
    }

    /// Expression formatted for nftables "meta mark set <expr>"
    pub fn to_nft_set_expr(&self) -> String {
        if let Some(mask) = self.mask {
            let not_mask = !mask;
            let set_val = self.mark & mask;
            format!("meta mark and 0x{:08x} or 0x{:x}", not_mask, set_val)
        } else {
            format!("0x{:x}", self.mark)
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "fitproxy",
    version,
    about = "Linux Fake IP + TPROXY DNS server and proxy"
)]
pub struct CliArgs {
    /// Proxy rule in the format <pattern>=<target>. Can be domain or IP CIDR. Can be specified multiple times.
    #[arg(long = "rule", value_name = "PATTERN=TARGET")]
    pub rules: Vec<String>,

    /// The fake IP CIDR range (IPv4 or IPv6).
    #[arg(
        long = "fakeip-range",
        value_name = "CIDR",
        default_value = "198.18.0.0/15"
    )]
    pub fakeip_range: String,

    /// Pre-assign static fake IP to domain in format <domain>=<ip>. Can be specified multiple times.
    #[arg(long = "fakeip", value_name = "DOMAIN=IP")]
    pub fakeip: Vec<String>,

    /// The TPROXY listen address [<ip>:]<port>.
    #[arg(long = "listen", value_name = "ADDR", default_value = "7080")]
    pub listen: String,

    /// The DNS server listen address [<ip>:]<port>.
    #[arg(long = "listen-dns", value_name = "ADDR", default_value = "7053")]
    pub listen_dns: String,

    /// The disk fakeip cache file path.
    #[arg(
        long = "cache",
        value_name = "PATH",
        default_value = "/tmp/fitproxy_fakeip"
    )]
    pub cache: PathBuf,

    /// Config file path.
    #[arg(
        short = 'c',
        long = "config",
        value_name = "PATH",
        default_value = "/etc/fitproxy.json"
    )]
    pub config: PathBuf,

    /// Disable automatic nftables and ip routing setup.
    #[arg(long = "no-network-setup")]
    pub no_network_setup: bool,

    /// Routing table ID for policy routing.
    #[arg(long = "table-id", default_value = "7080")]
    pub table_id: u32,

    /// Firewall mark for policy routing ("mark" or "mark/bitmask").
    #[arg(long = "fwmark", default_value = "0x8000/0x8000")]
    pub fwmark: String,

    /// Comma-separated list of network interfaces to match in TPROXY prerouting.
    #[arg(long = "interface", value_name = "INTERFACES")]
    pub interface: Option<String>,

    /// Firewall mark for fitproxy egress sockets ("mark" or "mark/bitmask").
    #[arg(long = "egress-mark", default_value = "0x10000/0x10000")]
    pub egress_mark: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct JsonConfigFile {
    pub rules: Option<Vec<String>>,
    pub fakeip_range: Option<String>,
    pub fakeip: Option<serde_json::Value>,
    pub listen: Option<String>,
    pub listen_dns: Option<String>,
    pub cache: Option<String>,
    pub setup_network: Option<bool>,
    pub table_id: Option<u32>,
    pub fwmark: Option<serde_json::Value>,
    pub interface: Option<serde_json::Value>,
    pub egress_mark: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub rules: RuleSet,
    pub fakeip_range: IpNet,
    pub static_fakeips: HashMap<String, IpAddr>,
    pub static_ip_to_domain: HashMap<IpAddr, String>,
    pub listen_addr: SocketAddr,
    pub listen_dns_addr: SocketAddr,
    pub cache_path: PathBuf,
    pub setup_network: bool,
    pub table_id: u32,
    pub fwmark: FwMark,
    pub interfaces: Vec<String>,
    pub egress_mark: FwMark,
}

pub fn parse_socket_addr(s: &str, default_port: u16, prefer_ipv6: bool) -> Result<SocketAddr, String> {
    let s = s.trim();
    if let Ok(port) = s.parse::<u16>() {
        return if prefer_ipv6 {
            Ok(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
        } else {
            Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        };
    }
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::from((ip, default_port)));
    }
    // Try ip:port or [ipv6]:port
    if let Some((ip_str, port_str)) = s.rsplit_once(':') {
        let ip_clean = ip_str.trim_matches('[').trim_matches(']');
        if let (Ok(ip), Ok(port)) = (ip_clean.parse::<IpAddr>(), port_str.parse::<u16>()) {
            return Ok(SocketAddr::from((ip, port)));
        }
    }
    Err(format!("Invalid address: '{}'", s))
}

pub fn parse_static_fakeip_str(s: &str) -> Result<(String, IpAddr), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid --fakeip format (expected domain=ip): '{}'",
            s
        ));
    }
    let domain = parts[0].trim().to_ascii_lowercase();
    let ip = parts[1]
        .trim()
        .parse::<IpAddr>()
        .map_err(|e| format!("Invalid IP in --fakeip '{}': {}", s, e))?;
    Ok((domain, ip))
}

impl AppConfig {
    pub fn load_and_merge(cli: CliArgs) -> Result<Self, String> {
        let mut file_config = JsonConfigFile::default();

        if cli.config.exists() {
            let content = fs::read_to_string(&cli.config)
                .map_err(|e| format!("Failed to read config file '{:?}': {}", cli.config, e))?;
            file_config = serde_json::from_str(&content).map_err(|e| {
                format!("Failed to parse JSON config file '{:?}': {}", cli.config, e)
            })?;
        }

        // Rules: CLI rules have precedence if provided, otherwise config file rules.
        let raw_rules = if !cli.rules.is_empty() {
            cli.rules
        } else if let Some(rules) = file_config.rules {
            rules
        } else {
            Vec::new()
        };

        if raw_rules.is_empty() {
            return Err("At least 1 rule must be provided (--rule or via config file), otherwise fitproxy will do nothing.".to_string());
        }

        let mut parsed_rules = Vec::new();
        for r in &raw_rules {
            parsed_rules.push(Rule::parse(r)?);
        }
        let rule_set = RuleSet::new(parsed_rules);

        // Fake IP range (IPv4 or IPv6)
        let fakeip_range_str =
            if cli.fakeip_range != "198.18.0.0/15" || file_config.fakeip_range.is_none() {
                cli.fakeip_range
            } else {
                file_config.fakeip_range.unwrap()
            };
        let fakeip_range: IpNet = fakeip_range_str
            .parse()
            .map_err(|e| format!("Invalid fake IP range '{}': {}", fakeip_range_str, e))?;

        let prefer_ipv6 = matches!(fakeip_range, IpNet::V6(_));

        // Static fake IPs
        let mut static_fakeips = HashMap::new();
        let mut static_ip_to_domain = HashMap::new();

        // Load static fakeips from config file first
        if let Some(val) = file_config.fakeip {
            match val {
                serde_json::Value::Object(map) => {
                    for (domain, ip_val) in map {
                        if let Some(ip_str) = ip_val.as_str() {
                            let ip: IpAddr = ip_str.parse().map_err(|e| {
                                format!("Invalid IP '{}' in config file: {}", ip_str, e)
                            })?;
                            let domain = domain.trim().to_ascii_lowercase();
                            static_ip_to_domain.insert(ip, domain.clone());
                            static_fakeips.insert(domain, ip);
                        }
                    }
                }
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            let (domain, ip) = parse_static_fakeip_str(s)?;
                            static_ip_to_domain.insert(ip, domain.clone());
                            static_fakeips.insert(domain, ip);
                        }
                    }
                }
                _ => {}
            }
        }

        // CLI static fakeips take precedence
        for s in &cli.fakeip {
            let (domain, ip) = parse_static_fakeip_str(s)?;
            static_ip_to_domain.insert(ip, domain.clone());
            static_fakeips.insert(domain, ip);
        }

        // Validate static fakeips are inside fakeip_range
        for (domain, ip) in &static_fakeips {
            if !fakeip_range.contains(ip) {
                return Err(format!(
                    "Static fake IP {} for domain '{}' is outside fake IP range {}",
                    ip, domain, fakeip_range
                ));
            }
        }

        // Listen addresses
        let listen_str = if cli.listen != "7080" || file_config.listen.is_none() {
            cli.listen
        } else {
            file_config.listen.unwrap()
        };
        let listen_addr = parse_socket_addr(&listen_str, 7080, prefer_ipv6)?;

        let listen_dns_str = if cli.listen_dns != "7053" || file_config.listen_dns.is_none() {
            cli.listen_dns
        } else {
            file_config.listen_dns.unwrap()
        };
        let listen_dns_addr = parse_socket_addr(&listen_dns_str, 7053, prefer_ipv6)?;

        // Cache path
        let cache_path =
            if cli.cache != Path::new("/tmp/fitproxy_fakeip") || file_config.cache.is_none() {
                cli.cache
            } else {
                PathBuf::from(file_config.cache.unwrap())
            };

        // Network setup
        let setup_network = if cli.no_network_setup {
            false
        } else if let Some(setup) = file_config.setup_network {
            setup
        } else {
            true
        };

        let table_id = file_config.table_id.unwrap_or(cli.table_id);

        let fwmark_str = if cli.fwmark != "0x8000/0x8000" || file_config.fwmark.is_none() {
            cli.fwmark
        } else {
            match file_config.fwmark.unwrap() {
                serde_json::Value::String(s) => s,
                serde_json::Value::Number(n) => n.to_string(),
                v => v.to_string(),
            }
        };
        let fwmark = FwMark::parse(&fwmark_str)?;

        // Interfaces
        let mut interfaces = Vec::new();
        if let Some(iface_str) = cli.interface {
            for item in iface_str.split(',') {
                let trimmed = item.trim();
                if !trimmed.is_empty() {
                    interfaces.push(trimmed.to_string());
                }
            }
        } else if let Some(val) = file_config.interface {
            match val {
                serde_json::Value::String(s) => {
                    for item in s.split(',') {
                        let trimmed = item.trim();
                        if !trimmed.is_empty() {
                            interfaces.push(trimmed.to_string());
                        }
                    }
                }
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            let trimmed = s.trim();
                            if !trimmed.is_empty() {
                                interfaces.push(trimmed.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Egress mark
        let egress_mark_str =
            if cli.egress_mark != "0x10000/0x10000" || file_config.egress_mark.is_none() {
                cli.egress_mark
            } else {
                match file_config.egress_mark.unwrap() {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Number(n) => n.to_string(),
                    v => v.to_string(),
                }
            };
        let egress_mark = FwMark::parse(&egress_mark_str)?;

        Ok(AppConfig {
            rules: rule_set,
            fakeip_range,
            static_fakeips,
            static_ip_to_domain,
            listen_addr,
            listen_dns_addr,
            cache_path,
            setup_network,
            table_id,
            fwmark,
            interfaces,
            egress_mark,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fwmark_parsing_and_formatting() {
        // Default format: "0x8000/0x8000"
        let f1 = FwMark::parse("0x8000/0x8000").unwrap();
        assert_eq!(f1.mark, 0x8000);
        assert_eq!(f1.mask, Some(0x8000));
        assert_eq!(f1.to_ip_rule_str(), "0x8000/0x8000");
        assert_eq!(f1.to_nft_set_expr(), "meta mark and 0xffff7fff or 0x8000");

        // Mark only format: "0x8000"
        let f2 = FwMark::parse("0x8000").unwrap();
        assert_eq!(f2.mark, 0x8000);
        assert_eq!(f2.mask, None);
        assert_eq!(f2.to_ip_rule_str(), "0x8000");
        assert_eq!(f2.to_nft_set_expr(), "0x8000");

        // Decimal mark/bitmask: "32768/32768"
        let f3 = FwMark::parse("32768/32768").unwrap();
        assert_eq!(f3.mark, 32768);
        assert_eq!(f3.mask, Some(32768));
        assert_eq!(f3.to_ip_rule_str(), "0x8000/0x8000");

        // Decimal mark only: "1"
        let f4 = FwMark::parse("1").unwrap();
        assert_eq!(f4.mark, 1);
        assert_eq!(f4.mask, None);
        assert_eq!(f4.to_ip_rule_str(), "0x1");
        assert_eq!(f4.to_nft_set_expr(), "0x1");
    }
}
