use clap::Parser;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::rules::{Rule, RuleSet};

#[derive(Parser, Debug)]
#[command(
    name = "fitproxy",
    version,
    about = "Linux Fake IP + TPROXY DNS server and proxy"
)]
pub struct CliArgs {
    /// Proxy rule in the format <domain>=<target>. Can be specified multiple times.
    #[arg(long = "rule", value_name = "DOMAIN=TARGET")]
    pub rules: Vec<String>,

    /// The fake IP CIDR range.
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

    /// Firewall mark for policy routing.
    #[arg(long = "fwmark", default_value = "32768")]
    pub fwmark: u32,
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
    pub fwmark: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub rules: RuleSet,
    pub fakeip_range: Ipv4Net,
    pub static_fakeips: HashMap<String, Ipv4Addr>,
    pub static_ip_to_domain: HashMap<Ipv4Addr, String>,
    pub listen_addr: SocketAddr,
    pub listen_dns_addr: SocketAddr,
    pub cache_path: PathBuf,
    pub setup_network: bool,
    pub table_id: u32,
    pub fwmark: u32,
}

pub fn parse_socket_addr(s: &str, default_port: u16) -> Result<SocketAddr, String> {
    let s = s.trim();
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::from((ip, default_port)));
    }
    // Try ip:port
    if let Some((ip_str, port_str)) = s.rsplit_once(':') {
        if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
            return Ok(SocketAddr::from((ip, port)));
        }
    }
    Err(format!("Invalid address: '{}'", s))
}

pub fn parse_static_fakeip_str(s: &str) -> Result<(String, Ipv4Addr), String> {
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
        .parse::<Ipv4Addr>()
        .map_err(|e| format!("Invalid IPv4 in --fakeip '{}': {}", s, e))?;
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

        // Fake IP range
        let fakeip_range_str =
            if cli.fakeip_range != "198.18.0.0/15" || file_config.fakeip_range.is_none() {
                cli.fakeip_range
            } else {
                file_config.fakeip_range.unwrap()
            };
        let fakeip_range: Ipv4Net = fakeip_range_str
            .parse()
            .map_err(|e| format!("Invalid fake IP range '{}': {}", fakeip_range_str, e))?;

        // Static fake IPs
        let mut static_fakeips = HashMap::new();
        let mut static_ip_to_domain = HashMap::new();

        // Load static fakeips from config file first
        if let Some(val) = file_config.fakeip {
            match val {
                serde_json::Value::Object(map) => {
                    for (domain, ip_val) in map {
                        if let Some(ip_str) = ip_val.as_str() {
                            let ip: Ipv4Addr = ip_str.parse().map_err(|e| {
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
        let listen_addr = parse_socket_addr(&listen_str, 7080)?;

        let listen_dns_str = if cli.listen_dns != "7053" || file_config.listen_dns.is_none() {
            cli.listen_dns
        } else {
            file_config.listen_dns.unwrap()
        };
        let listen_dns_addr = parse_socket_addr(&listen_dns_str, 7053)?;

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
        let fwmark = file_config.fwmark.unwrap_or(cli.fwmark);

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
        })
    }
}
