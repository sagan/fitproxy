use ipnet::IpNet;
use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{debug, info};

use crate::config::FwMark;

pub struct NetworkManager {
    fakeip_range: IpNet,
    allowed_ip_cidrs: Vec<IpNet>,
    output_ip_cidrs: Vec<IpNet>,
    listen_port: u16,
    table_id: u32,
    fwmark: FwMark,
    egress_mark: FwMark,
    interfaces: Vec<String>,
    active: bool,
}

impl NetworkManager {
    pub fn new(
        fakeip_range: IpNet,
        allowed_ip_cidrs: Vec<IpNet>,
        output_ip_cidrs: Vec<IpNet>,
        listen_port: u16,
        table_id: u32,
        fwmark: FwMark,
        egress_mark: FwMark,
        interfaces: Vec<String>,
    ) -> Self {
        NetworkManager {
            fakeip_range,
            allowed_ip_cidrs,
            output_ip_cidrs,
            listen_port,
            table_id,
            fwmark,
            egress_mark,
            interfaces,
            active: false,
        }
    }

    pub fn generate_nft_script(&self) -> String {
        let mut prerouting_v4 = Vec::new();
        let mut prerouting_v6 = Vec::new();

        match self.fakeip_range {
            IpNet::V4(net) => prerouting_v4.push(IpNet::V4(net)),
            IpNet::V6(net) => prerouting_v6.push(IpNet::V6(net)),
        }

        for cidr in &self.allowed_ip_cidrs {
            match cidr {
                IpNet::V4(net) => {
                    if !prerouting_v4.contains(&IpNet::V4(*net)) {
                        prerouting_v4.push(IpNet::V4(*net));
                    }
                }
                IpNet::V6(net) => {
                    if !prerouting_v6.contains(&IpNet::V6(*net)) {
                        prerouting_v6.push(IpNet::V6(*net));
                    }
                }
            }
        }

        let mut output_v4 = Vec::new();
        let mut output_v6 = Vec::new();

        match self.fakeip_range {
            IpNet::V4(net) => output_v4.push(IpNet::V4(net)),
            IpNet::V6(net) => output_v6.push(IpNet::V6(net)),
        }

        for cidr in &self.output_ip_cidrs {
            match cidr {
                IpNet::V4(net) => {
                    if !output_v4.contains(&IpNet::V4(*net)) {
                        output_v4.push(IpNet::V4(*net));
                    }
                }
                IpNet::V6(net) => {
                    if !output_v6.contains(&IpNet::V6(*net)) {
                        output_v6.push(IpNet::V6(*net));
                    }
                }
            }
        }

        let nft_set_mark_expr = self.fwmark.to_nft_set_expr();
        let egress_mask = self.egress_mark.mask.unwrap_or(self.egress_mark.mark);
        let egress_val = self.egress_mark.mark & egress_mask;
        let nft_egress_exclude_expr = format!(
            "meta mark and 0x{:x} == 0x{:x} accept",
            egress_mask, egress_val
        );

        let iif_clause = if !self.interfaces.is_empty() {
            let mut ifaces = self.interfaces.clone();
            if !ifaces.iter().any(|i| i == "lo") {
                ifaces.push("lo".to_string());
            }
            let formatted_ifaces = ifaces
                .iter()
                .map(|i| format!("\"{}\"", i))
                .collect::<Vec<_>>()
                .join(", ");
            format!("iifname {{ {} }} ", formatted_ifaces)
        } else {
            String::new()
        };

        let mut prerouting_rules = Vec::new();
        prerouting_rules.push(format!("        {}\n", nft_egress_exclude_expr));

        if !prerouting_v4.is_empty() {
            let v4_set = prerouting_v4
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            prerouting_rules.push(format!(
                "        {}fib daddr type != local ip daddr {{ {} }} meta l4proto {{ tcp, udp }} tproxy ip to :{} meta mark set {} accept\n",
                iif_clause, v4_set, self.listen_port, nft_set_mark_expr
            ));
        }

        if !prerouting_v6.is_empty() {
            let v6_set = prerouting_v6
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            prerouting_rules.push(format!(
                "        {}fib daddr type != local ip6 daddr {{ {} }} meta l4proto {{ tcp, udp }} tproxy ip6 to :{} meta mark set {} accept\n",
                iif_clause, v6_set, self.listen_port, nft_set_mark_expr
            ));
        }

        let mut output_rules = Vec::new();
        output_rules.push(format!("        {}\n", nft_egress_exclude_expr));
        output_rules.push("        ct direction reply accept\n".to_string());

        if !output_v4.is_empty() {
            let v4_set = output_v4
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            output_rules.push(format!(
                "        fib daddr type != local ip daddr {{ {} }} meta l4proto {{ tcp, udp }} meta mark set {} accept\n",
                v4_set, nft_set_mark_expr
            ));
        }

        if !output_v6.is_empty() {
            let v6_set = output_v6
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            output_rules.push(format!(
                "        fib daddr type != local ip6 daddr {{ {} }} meta l4proto {{ tcp, udp }} meta mark set {} accept\n",
                v6_set, nft_set_mark_expr
            ));
        }

        format!(
            "table inet fitproxy {{\n\
             \x20   chain prerouting {{\n\
             \x20       type filter hook prerouting priority mangle - 1; policy accept;\n\
             {}\
             \x20   }}\n\
             \x20   chain output {{\n\
             \x20       type route hook output priority mangle - 1; policy accept;\n\
             {}\
             \x20   }}\n\
             }}\n",
            prerouting_rules.concat(),
            output_rules.concat()
        )
    }

    pub fn setup(&mut self) -> Result<(), String> {
        info!("Setting up system routing and nftables TPROXY rules...");

        // 1. Idempotent cleanup of any stale rules first
        self.cleanup_internal();

        let mut v4_cidrs = Vec::new();
        let mut v6_cidrs = Vec::new();

        match self.fakeip_range {
            IpNet::V4(net) => v4_cidrs.push(IpNet::V4(net)),
            IpNet::V6(net) => v6_cidrs.push(IpNet::V6(net)),
        }

        for cidr in &self.allowed_ip_cidrs {
            match cidr {
                IpNet::V4(net) => {
                    if !v4_cidrs.contains(&IpNet::V4(*net)) {
                        v4_cidrs.push(IpNet::V4(*net));
                    }
                }
                IpNet::V6(net) => {
                    if !v6_cidrs.contains(&IpNet::V6(*net)) {
                        v6_cidrs.push(IpNet::V6(*net));
                    }
                }
            }
        }

        let need_v4 = !v4_cidrs.is_empty();
        let need_v6 = !v6_cidrs.is_empty();
        let table_1 = self.table_id;
        let table_2 = self.table_id + 1;
        let fwmark_str = self.fwmark.to_ip_rule_str();
        let fakeip_str = self.fakeip_range.to_string();

        // 2. Setup policy routing:
        // Rule 1: from all fwmark <fwmark> lookup <table_1> (prio 3)
        // Rule 2: from all lookup <table_2> (prio 4)
        if need_v6 {
            let rule1_status = Command::new("ip")
                .args([
                    "-6",
                    "rule",
                    "add",
                    "pref",
                    "3",
                    "fwmark",
                    &fwmark_str,
                    "lookup",
                    &table_1.to_string(),
                ])
                .status();
            match rule1_status {
                Ok(s) if s.success() => debug!(
                    "Added ip -6 rule pref 3 fwmark {} lookup {}",
                    fwmark_str, table_1
                ),
                Ok(s) => {
                    return Err(format!(
                        "Failed to add ip -6 rule pref 3 (exit code: {}). Root / CAP_NET_ADMIN required.",
                        s
                    ));
                }
                Err(e) => return Err(format!("Failed to execute 'ip -6 rule' command: {}", e)),
            }

            let route1_status = Command::new("ip")
                .args([
                    "-6",
                    "route",
                    "replace",
                    "local",
                    "default",
                    "dev",
                    "lo",
                    "table",
                    &table_1.to_string(),
                ])
                .status();
            match route1_status {
                Ok(s) if s.success() => debug!("Added ip -6 local route to table {}", table_1),
                Ok(s) => {
                    return Err(format!(
                        "Failed to add ip -6 route to table {} (exit code: {})",
                        table_1, s
                    ));
                }
                Err(e) => return Err(format!("Failed to execute 'ip -6 route' command: {}", e)),
            }

            if matches!(self.fakeip_range, IpNet::V6(_)) {
                let rule2_status = Command::new("ip")
                    .args([
                        "-6",
                        "rule",
                        "add",
                        "pref",
                        "4",
                        "lookup",
                        &table_2.to_string(),
                    ])
                    .status();
                match rule2_status {
                    Ok(s) if s.success() => debug!("Added ip -6 rule pref 4 lookup {}", table_2),
                    Ok(s) => {
                        return Err(format!(
                            "Failed to add ip -6 rule pref 4 (exit code: {}). Root / CAP_NET_ADMIN required.",
                            s
                        ));
                    }
                    Err(e) => return Err(format!("Failed to execute 'ip -6 rule' command: {}", e)),
                }

                let route2_status = Command::new("ip")
                    .args([
                        "-6",
                        "route",
                        "replace",
                        &fakeip_str,
                        "dev",
                        "lo",
                        "table",
                        &table_2.to_string(),
                    ])
                    .status();
                match route2_status {
                    Ok(s) if s.success() => debug!(
                        "Added ip -6 fakeip route {} to table {}",
                        fakeip_str, table_2
                    ),
                    Ok(s) => {
                        return Err(format!(
                            "Failed to add ip -6 route to table {} (exit code: {})",
                            table_2, s
                        ));
                    }
                    Err(e) => {
                        return Err(format!("Failed to execute 'ip -6 route' command: {}", e));
                    }
                }
            }
        }

        if need_v4 {
            let rule1_status = Command::new("ip")
                .args([
                    "rule",
                    "add",
                    "pref",
                    "3",
                    "fwmark",
                    &fwmark_str,
                    "lookup",
                    &table_1.to_string(),
                ])
                .status();
            match rule1_status {
                Ok(s) if s.success() => debug!(
                    "Added ip rule pref 3 fwmark {} lookup {}",
                    fwmark_str, table_1
                ),
                Ok(s) => {
                    return Err(format!(
                        "Failed to add ip rule pref 3 (exit code: {}). Root / CAP_NET_ADMIN required.",
                        s
                    ));
                }
                Err(e) => return Err(format!("Failed to execute 'ip rule' command: {}", e)),
            }

            let route1_status = Command::new("ip")
                .args([
                    "route",
                    "replace",
                    "local",
                    "default",
                    "dev",
                    "lo",
                    "scope",
                    "host",
                    "table",
                    &table_1.to_string(),
                ])
                .status();
            match route1_status {
                Ok(s) if s.success() => debug!("Added ip local default route to table {}", table_1),
                Ok(s) => {
                    return Err(format!(
                        "Failed to add ip route to table {} (exit code: {})",
                        table_1, s
                    ));
                }
                Err(e) => return Err(format!("Failed to execute 'ip route' command: {}", e)),
            }

            if matches!(self.fakeip_range, IpNet::V4(_)) {
                let rule2_status = Command::new("ip")
                    .args(["rule", "add", "pref", "4", "lookup", &table_2.to_string()])
                    .status();
                match rule2_status {
                    Ok(s) if s.success() => debug!("Added ip rule pref 4 lookup {}", table_2),
                    Ok(s) => {
                        return Err(format!(
                            "Failed to add ip rule pref 4 (exit code: {}). Root / CAP_NET_ADMIN required.",
                            s
                        ));
                    }
                    Err(e) => return Err(format!("Failed to execute 'ip rule' command: {}", e)),
                }

                let route2_status = Command::new("ip")
                    .args([
                        "route",
                        "replace",
                        &fakeip_str,
                        "dev",
                        "lo",
                        "scope",
                        "link",
                        "table",
                        &table_2.to_string(),
                    ])
                    .status();
                match route2_status {
                    Ok(s) if s.success() => {
                        debug!("Added ip fakeip route {} to table {}", fakeip_str, table_2)
                    }
                    Ok(s) => {
                        return Err(format!(
                            "Failed to add ip route to table {} (exit code: {})",
                            table_2, s
                        ));
                    }
                    Err(e) => return Err(format!("Failed to execute 'ip route' command: {}", e)),
                }
            }
        }

        // 3. Setup nftables ruleset
        let nft_script = self.generate_nft_script();

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn 'nft' command: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(nft_script.as_bytes())
                .map_err(|e| format!("Failed to write nftables configuration: {}", e))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("Failed to wait for 'nft' process: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("nftables setup failed: {}", stderr.trim()));
        }

        self.active = true;
        info!("Successfully configured nftables table inet fitproxy and routing rules");
        Ok(())
    }

    pub fn teardown(&mut self) {
        if self.active {
            info!("Cleaning up system routing and nftables rules...");
            self.cleanup_internal();
            self.active = false;
        }
    }

    fn cleanup_internal(&self) {
        // Delete nftables table inet fitproxy
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "fitproxy"])
            .output();

        let table_1 = self.table_id.to_string();
        let table_2 = (self.table_id + 1).to_string();

        // IPv4 cleanup
        let _ = Command::new("ip")
            .args(["rule", "del", "pref", "3"])
            .output();
        let _ = Command::new("ip")
            .args(["rule", "del", "pref", "4"])
            .output();
        let _ = Command::new("ip")
            .args(["route", "flush", "table", &table_1])
            .output();
        let _ = Command::new("ip")
            .args(["route", "flush", "table", &table_2])
            .output();

        // IPv6 cleanup
        let _ = Command::new("ip")
            .args(["-6", "rule", "del", "pref", "3"])
            .output();
        let _ = Command::new("ip")
            .args(["-6", "rule", "del", "pref", "4"])
            .output();
        let _ = Command::new("ip")
            .args(["-6", "route", "flush", "table", &table_1])
            .output();
        let _ = Command::new("ip")
            .args(["-6", "route", "flush", "table", &table_2])
            .output();
    }
}

impl Drop for NetworkManager {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nft_script_basic() {
        let fakeip = "198.18.0.0/15".parse().unwrap();
        let fwmark = FwMark::parse("0x8000/0x8000").unwrap();
        let egress_mark = FwMark::parse("0x10000/0x10000").unwrap();
        let nm = NetworkManager::new(
            fakeip,
            vec!["0.0.0.0/0".parse().unwrap()],
            vec!["0.0.0.0/0".parse().unwrap()],
            7080,
            7080,
            fwmark,
            egress_mark,
            vec!["eth0".to_string()],
        );

        let script = nm.generate_nft_script();
        assert!(script.contains("meta mark and 0x10000 == 0x10000 accept"));
        assert!(script.contains("ct direction reply accept"));
        assert!(script.contains("iifname { \"eth0\", \"lo\" } fib daddr type != local ip daddr { 198.18.0.0/15, 0.0.0.0/0 } meta l4proto { tcp, udp } tproxy ip to :7080"));
        assert!(script.contains("ip daddr { 198.18.0.0/15, 0.0.0.0/0 } meta l4proto { tcp, udp } meta mark set"));
    }

    #[test]
    fn test_generate_nft_script_multi_interface_and_v6() {
        let fakeip = "198.18.0.0/15".parse().unwrap();
        let fwmark = FwMark::parse("0x8000/0x8000").unwrap();
        let egress_mark = FwMark::parse("0x10000/0x10000").unwrap();
        let nm = NetworkManager::new(
            fakeip,
            vec!["::/0".parse().unwrap()],
            vec!["::/0".parse().unwrap()],
            7080,
            7080,
            fwmark,
            egress_mark,
            vec!["eth0".to_string(), "eth1".to_string()],
        );

        let script = nm.generate_nft_script();
        assert!(script.contains(
            "iifname { \"eth0\", \"eth1\", \"lo\" } fib daddr type != local ip daddr { 198.18.0.0/15 }"
        ));
        assert!(
            script.contains(
                "iifname { \"eth0\", \"eth1\", \"lo\" } fib daddr type != local ip6 daddr { ::/0 }"
            )
        );
    }

    #[test]
    fn test_generate_nft_script_excludes_direct_from_output() {
        let fakeip = "fd42:a159:f9f0:1ca::/64".parse().unwrap();
        let fwmark = FwMark::parse("0x8000/0x8000").unwrap();
        let egress_mark = FwMark::parse("0x10000/0x10000").unwrap();
        // allowed_ip_cidrs has 0.0.0.0/0 (direct for prerouting), but output_ip_cidrs is empty
        let nm = NetworkManager::new(
            fakeip,
            vec!["0.0.0.0/0".parse().unwrap()],
            vec![], // no non-direct CIDRs for output
            7080,
            7080,
            fwmark,
            egress_mark,
            vec!["wg42*".to_string()],
        );

        let script = nm.generate_nft_script();
        // Prerouting should have 0.0.0.0/0
        assert!(script.contains("ip daddr { 0.0.0.0/0 } meta l4proto { tcp, udp } tproxy ip to :7080"));
        // Output chain should NOT have any IPv4 mark rule because 0.0.0.0/0 was direct
        let output_chain = script.split("chain output {").nth(1).unwrap();
        assert!(!output_chain.contains("ip daddr"));
        // Output chain should only have IPv6 fakeip range
        assert!(output_chain.contains("ip6 daddr { fd42:a159:f9f0:1ca::/64 } meta l4proto { tcp, udp } meta mark set"));
    }
}
