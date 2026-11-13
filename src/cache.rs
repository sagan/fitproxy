use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::rules::RuleSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheRecord {
    pub domain: String,
    pub ip: IpAddr,
    #[serde(default)]
    pub ts: u64,
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct DiskCache {
    path: PathBuf,
    writer_lock: Mutex<()>,
}

impl DiskCache {
    pub fn new(path: PathBuf) -> Self {
        DiskCache {
            path,
            writer_lock: Mutex::new(()),
        }
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a single allocation record to the JSONL log file.
    pub fn append(&self, domain: &str, ip: IpAddr) -> std::io::Result<()> {
        let _guard = self.writer_lock.lock().unwrap();

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        let record = CacheRecord {
            domain: domain.to_string(),
            ip,
            ts: current_timestamp(),
        };

        let mut json = serde_json::to_string(&record)?;
        json.push('\n');
        file.write_all(json.as_bytes())?;
        file.flush()?;
        Ok(())
    }

    /// Load persisted allocations from disk, validating against the current rules,
    /// fake IP CIDR range, and static fake IP assignments.
    /// Deduplicates and immediately compacts the cache file on startup.
    pub fn load_and_clean(
        &self,
        valid_range: &IpNet,
        rule_set: &RuleSet,
        static_fakeips: &HashMap<String, IpAddr>,
        static_ip_to_domain: &HashMap<IpAddr, String>,
    ) -> std::io::Result<(HashMap<String, IpAddr>, HashMap<IpAddr, String>)> {
        let _guard = self.writer_lock.lock().unwrap();

        let mut domain_to_ip: HashMap<String, IpAddr> = HashMap::new();
        let mut ip_to_domain: HashMap<IpAddr, String> = HashMap::new();

        if !self.path.exists() {
            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)?;
            }
            File::create(&self.path)?;
            return Ok((domain_to_ip, ip_to_domain));
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);

        let mut total_lines = 0;
        let mut valid_entries = 0;

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!("Error reading line from cache file {:?}: {}", self.path, e);
                    continue;
                }
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            total_lines += 1;

            let record: CacheRecord = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(e) => {
                    debug!(
                        "Skipping malformed cache line in {:?}: {} ({})",
                        self.path, line, e
                    );
                    continue;
                }
            };

            let domain = record.domain.trim().to_ascii_lowercase();
            let ip = record.ip;

            // 1. IP must be in fake IP range
            if !valid_range.contains(&ip) {
                debug!(
                    "Discarding cache record {}={}: outside fake IP range",
                    domain, ip
                );
                continue;
            }

            // 2. IP must not collide with static fake IP of another domain
            if let Some(static_domain) = static_ip_to_domain.get(&ip) {
                if *static_domain != domain {
                    debug!(
                        "Discarding cache record {}={}: conflicts with static fake IP for {}",
                        domain, ip, static_domain
                    );
                    continue;
                }
            }

            // 3. Domain must not have a different static fake IP
            if let Some(&static_ip) = static_fakeips.get(&domain) {
                if static_ip != ip {
                    debug!(
                        "Discarding cache record {}={}: superseded by static fake IP {}",
                        domain, ip, static_ip
                    );
                    continue;
                }
            }

            // 4. Domain must be allowed by current rules
            if !rule_set.is_allowed(&domain) {
                debug!(
                    "Discarding cache record {}={}: domain no longer allowed by rules",
                    domain, ip
                );
                continue;
            }

            // Valid! Sequential replay handles updates
            // Clean up any previous reverse mapping if IP changed
            if let Some(old_ip) = domain_to_ip.get(&domain) {
                ip_to_domain.remove(old_ip);
            }
            // Clean up any previous domain if IP was reassigned
            if let Some(old_domain) = ip_to_domain.get(&ip) {
                domain_to_ip.remove(old_domain);
            }

            domain_to_ip.insert(domain.clone(), ip);
            ip_to_domain.insert(ip, domain);
            valid_entries += 1;
        }

        info!(
            "Loaded cache from {:?}: {} total lines read, {} valid entries, {} unique active mappings restored",
            self.path,
            total_lines,
            valid_entries,
            domain_to_ip.len()
        );

        // Deduplicate and re-create clean file on startup
        Self::compact_internal(&self.path, &domain_to_ip)?;

        Ok((domain_to_ip, ip_to_domain))
    }

    /// Rewrite active records to a temporary file and atomically rename.
    pub fn compact(&self, active_records: &HashMap<String, IpAddr>) -> std::io::Result<()> {
        let _guard = self.writer_lock.lock().unwrap();
        Self::compact_internal(&self.path, active_records)
    }

    fn compact_internal(path: &Path, records: &HashMap<String, IpAddr>) -> std::io::Result<()> {
        let tmp_path = path.with_extension("tmp");
        if let Some(parent) = tmp_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let now = current_timestamp();
        {
            let mut file = File::create(&tmp_path)?;
            for (domain, ip) in records {
                let rec = CacheRecord {
                    domain: domain.clone(),
                    ip: *ip,
                    ts: now,
                };
                let mut json = serde_json::to_string(&rec)?;
                json.push('\n');
                file.write_all(json.as_bytes())?;
            }
            file.flush()?;
            file.sync_all()?;
        }

        fs::rename(&tmp_path, path)?;
        debug!(
            "Compacted cache file {:?} ({} records)",
            path,
            records.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;
    use std::str::FromStr;

    #[test]
    fn test_cache_append_and_load_dedup() {
        let temp_dir = std::env::temp_dir().join(format!("fitproxy_test_{}", current_timestamp()));
        let cache_path = temp_dir.join("test_cache.jsonl");

        let cache = DiskCache::new(cache_path.clone());
        let ip1 = IpAddr::from_str("198.18.0.2").unwrap();
        let ip2 = IpAddr::from_str("198.18.0.3").unwrap();
        let ip3 = IpAddr::from_str("198.18.0.4").unwrap();

        cache.append("example.com", ip1).unwrap();
        cache.append("example.com", ip2).unwrap(); // updated IP for same domain
        cache.append("test.org", ip3).unwrap();
        cache
            .append("bad.com", IpAddr::from_str("198.18.0.5").unwrap())
            .unwrap();

        let range = IpNet::from_str("198.18.0.0/15").unwrap();
        let rules = RuleSet::new(vec![
            Rule::parse("example.com=direct").unwrap(),
            Rule::parse("test.org=direct").unwrap(),
            Rule::parse("bad.com=reject").unwrap(),
        ]);

        let static_fakeips = HashMap::new();
        let static_ip_to_domain = HashMap::new();

        let (domain_to_ip, ip_to_domain) = cache
            .load_and_clean(&range, &rules, &static_fakeips, &static_ip_to_domain)
            .unwrap();

        // bad.com rejected by rule, example.com updated to ip2, test.org is ip3
        assert_eq!(domain_to_ip.len(), 2);
        assert_eq!(domain_to_ip.get("example.com"), Some(&ip2));
        assert_eq!(domain_to_ip.get("test.org"), Some(&ip3));
        assert_eq!(domain_to_ip.get("bad.com"), None);

        assert_eq!(ip_to_domain.get(&ip2), Some(&"example.com".to_string()));
        assert_eq!(ip_to_domain.get(&ip3), Some(&"test.org".to_string()));

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_cache_ipv6_support() {
        let temp_dir =
            std::env::temp_dir().join(format!("fitproxy_test_v6_{}", current_timestamp()));
        let cache_path = temp_dir.join("test_cache_v6.jsonl");

        let cache = DiskCache::new(cache_path.clone());
        let ip1 = IpAddr::from_str("fc00::2").unwrap();
        let ip2 = IpAddr::from_str("fc00::3").unwrap();

        cache.append("example.com", ip1).unwrap();
        cache.append("test.org", ip2).unwrap();

        let range = IpNet::from_str("fc00::/18").unwrap();
        let rules = RuleSet::new(vec![
            Rule::parse("example.com=direct").unwrap(),
            Rule::parse("test.org=direct").unwrap(),
        ]);

        let (domain_to_ip, ip_to_domain) = cache
            .load_and_clean(&range, &rules, &HashMap::new(), &HashMap::new())
            .unwrap();

        assert_eq!(domain_to_ip.get("example.com"), Some(&ip1));
        assert_eq!(domain_to_ip.get("test.org"), Some(&ip2));
        assert_eq!(ip_to_domain.get(&ip1), Some(&"example.com".to_string()));

        let _ = fs::remove_dir_all(temp_dir);
    }
}
