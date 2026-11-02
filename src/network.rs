use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{debug, info};

pub struct NetworkManager {
    fakeip_range: String,
    listen_port: u16,
    table_id: u32,
    fwmark: u32,
    active: bool,
}

impl NetworkManager {
    pub fn new(fakeip_range: String, listen_port: u16, table_id: u32, fwmark: u32) -> Self {
        NetworkManager {
            fakeip_range,
            listen_port,
            table_id,
            fwmark,
            active: false,
        }
    }

    pub fn setup(&mut self) -> Result<(), String> {
        info!("Setting up system routing and nftables TPROXY rules...");

        // 1. Idempotent cleanup of any stale rules first
        self.cleanup_internal();

        // 2. Setup policy routing:
        // ip route replace local 0.0.0.0/0 dev lo table <table_id>
        let route_status = Command::new("ip")
            .args([
                "route",
                "replace",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                &self.table_id.to_string(),
            ])
            .status();

        match route_status {
            Ok(status) if status.success() => {
                debug!("Added local route to table {}", self.table_id);
            }
            Ok(status) => {
                return Err(format!(
                    "Failed to add ip route local (exit code: {}). Are you root / CAP_NET_ADMIN?",
                    status
                ));
            }
            Err(e) => {
                return Err(format!("Failed to execute 'ip' command: {}", e));
            }
        }

        // ip rule add fwmark <fwmark> lookup <table_id>
        let rule_status = Command::new("ip")
            .args([
                "rule",
                "add",
                "fwmark",
                &self.fwmark.to_string(),
                "lookup",
                &self.table_id.to_string(),
            ])
            .status();

        match rule_status {
            Ok(status) if status.success() => {
                debug!(
                    "Added ip rule fwmark {} lookup {}",
                    self.fwmark, self.table_id
                );
            }
            Ok(status) => {
                return Err(format!("Failed to add ip rule (exit code: {})", status));
            }
            Err(e) => {
                return Err(format!("Failed to execute 'ip' command: {}", e));
            }
        }

        // 3. Setup nftables ruleset
        let nft_script = format!(
            "table inet fitproxy {{\n\
             \x20   chain prerouting {{\n\
             \x20       type filter hook prerouting priority mangle - 1; policy accept;\n\
             \x20       ip daddr {} meta l4proto tcp tproxy ip to :{} meta mark set {} accept\n\
             \x20   }}\n\
             \x20   chain output {{\n\
             \x20       type route hook output priority mangle - 1; policy accept;\n\
             \x20       ip daddr {} meta mark set {} accept\n\
             \x20   }}\n\
             }}\n",
            self.fakeip_range, self.listen_port, self.fwmark, self.fakeip_range, self.fwmark
        );

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

        // Delete ip rule
        let _ = Command::new("ip")
            .args([
                "rule",
                "del",
                "fwmark",
                &self.fwmark.to_string(),
                "lookup",
                &self.table_id.to_string(),
            ])
            .output();

        // Flush ip route table
        let _ = Command::new("ip")
            .args(["route", "flush", "table", &self.table_id.to_string()])
            .output();
    }
}

impl Drop for NetworkManager {
    fn drop(&mut self) {
        self.teardown();
    }
}
