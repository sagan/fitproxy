use ipnet::IpNet;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::cache::DiskCache;

fn u128_to_ip(val: u128, is_ipv6: bool) -> IpAddr {
    if is_ipv6 {
        IpAddr::V6(Ipv6Addr::from(val))
    } else {
        IpAddr::V4(Ipv4Addr::from(val as u32))
    }
}

pub struct FakeIpInner {
    start_ip: u128,
    end_ip: u128,
    cursor: u128,
    is_ipv6: bool,

    static_domain_to_ip: HashMap<String, IpAddr>,
    static_ip_to_domain: HashMap<IpAddr, String>,

    dynamic_domain_to_ip: HashMap<String, IpAddr>,
    dynamic_ip_to_domain: HashMap<IpAddr, String>,

    // Tracks allocation order for LRU eviction when pool is exhausted
    alloc_order: VecDeque<IpAddr>,
    // Active connections per IP to prevent recycling an IP in use
    active_conns: HashMap<IpAddr, usize>,
}

#[derive(Clone)]
pub struct FakeIpManager {
    inner: Arc<RwLock<FakeIpInner>>,
    range: IpNet,
    cache: Arc<DiskCache>,
}

impl FakeIpManager {
    pub fn new(
        range: IpNet,
        static_fakeips: HashMap<String, IpAddr>,
        static_ip_to_domain: HashMap<IpAddr, String>,
        initial_domain_to_ip: HashMap<String, IpAddr>,
        initial_ip_to_domain: HashMap<IpAddr, String>,
        cache: Arc<DiskCache>,
    ) -> Self {
        let is_ipv6 = matches!(range, IpNet::V6(_));
        let (start_ip, end_ip) = match range {
            IpNet::V4(net) => {
                let net_addr = u32::from(net.network()) as u128;
                let bcast_addr = u32::from(net.broadcast()) as u128;
                let s = net_addr + 1;
                let e = if bcast_addr > s { bcast_addr - 1 } else { s };
                (s, e)
            }
            IpNet::V6(net) => {
                let net_addr = u128::from_be_bytes(net.network().octets());
                let bcast_addr = u128::from_be_bytes(net.broadcast().octets());
                // Skip the subnet router anycast address (RFC 4291)
                let s = net_addr.saturating_add(1);
                let e = bcast_addr;
                (s, e)
            }
        };

        let mut alloc_order = VecDeque::new();
        for ip in initial_ip_to_domain.keys() {
            alloc_order.push_back(*ip);
        }

        let inner = FakeIpInner {
            start_ip,
            end_ip,
            cursor: start_ip,
            is_ipv6,
            static_domain_to_ip: static_fakeips,
            static_ip_to_domain,
            dynamic_domain_to_ip: initial_domain_to_ip,
            dynamic_ip_to_domain: initial_ip_to_domain,
            alloc_order,
            active_conns: HashMap::new(),
        };

        FakeIpManager {
            inner: Arc::new(RwLock::new(inner)),
            range,
            cache,
        }
    }

    pub fn range(&self) -> &IpNet {
        &self.range
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self.range, IpNet::V6(_))
    }

    pub fn is_fake_ip(&self, ip: &IpAddr) -> bool {
        self.range.contains(ip)
    }

    /// Look up existing fake IP or allocate a new one dynamically.
    pub fn lookup_or_allocate(&self, domain: &str) -> Option<IpAddr> {
        let domain_norm = domain.trim().to_ascii_lowercase();

        // 1. Read lock check
        {
            let inner = self.inner.read();
            if let Some(&ip) = inner.static_domain_to_ip.get(&domain_norm) {
                return Some(ip);
            }
            if let Some(&ip) = inner.dynamic_domain_to_ip.get(&domain_norm) {
                return Some(ip);
            }
        }

        // 2. Write lock allocate
        let mut inner = self.inner.write();

        // Re-check in case another thread allocated in the meantime
        if let Some(&ip) = inner.static_domain_to_ip.get(&domain_norm) {
            return Some(ip);
        }
        if let Some(&ip) = inner.dynamic_domain_to_ip.get(&domain_norm) {
            return Some(ip);
        }

        // Allocate a new IP (cap search attempts to prevent long loops on huge IPv6 subnets)
        let total_possible = inner
            .end_ip
            .saturating_sub(inner.start_ip)
            .saturating_add(1);
        let max_search = if total_possible > 262_144 {
            262_144
        } else {
            total_possible as usize
        };

        let mut allocated_ip = None;

        for _ in 0..max_search {
            let candidate_u128 = inner.cursor;
            inner.cursor = if inner.cursor >= inner.end_ip {
                inner.start_ip
            } else {
                inner.cursor.saturating_add(1)
            };

            let candidate_ip = u128_to_ip(candidate_u128, inner.is_ipv6);

            if !inner.static_ip_to_domain.contains_key(&candidate_ip)
                && !inner.dynamic_ip_to_domain.contains_key(&candidate_ip)
            {
                allocated_ip = Some(candidate_ip);
                break;
            }
        }

        // If pool is exhausted, find oldest entry with 0 active connections to evict
        if allocated_ip.is_none() {
            let mut evicted_ip = None;
            let mut checked = 0;
            let total_allocated = inner.alloc_order.len();

            while checked < total_allocated {
                if let Some(candidate) = inner.alloc_order.pop_front() {
                    let active = inner.active_conns.get(&candidate).copied().unwrap_or(0);
                    if active == 0 {
                        // Found eviction candidate
                        if let Some(old_domain) = inner.dynamic_ip_to_domain.remove(&candidate) {
                            inner.dynamic_domain_to_ip.remove(&old_domain);
                            debug!(
                                "Evicted inactive fake IP {} (previously {})",
                                candidate, old_domain
                            );
                        }
                        evicted_ip = Some(candidate);
                        break;
                    } else {
                        // Still active, push to back
                        inner.alloc_order.push_back(candidate);
                        checked += 1;
                    }
                } else {
                    break;
                }
            }

            allocated_ip = evicted_ip;
        }

        let ip = match allocated_ip {
            Some(ip) => ip,
            None => {
                warn!("Fake IP pool exhausted and all allocated IPs are currently in active use!");
                return None;
            }
        };

        inner.dynamic_domain_to_ip.insert(domain_norm.clone(), ip);
        inner.dynamic_ip_to_domain.insert(ip, domain_norm.clone());
        inner.alloc_order.push_back(ip);

        // Append to disk cache log
        if let Err(e) = self.cache.append(&domain_norm, ip) {
            warn!("Failed to append fake IP allocation to disk cache: {}", e);
        }

        debug!("Allocated fake IP {} for domain '{}'", ip, domain_norm);
        Some(ip)
    }

    /// Resolve a fake IP back to its original domain name.
    pub fn get_domain(&self, ip: &IpAddr) -> Option<String> {
        let inner = self.inner.read();
        if let Some(d) = inner.static_ip_to_domain.get(ip) {
            return Some(d.clone());
        }
        if let Some(d) = inner.dynamic_ip_to_domain.get(ip) {
            return Some(d.clone());
        }
        None
    }

    pub fn inc_conn(&self, ip: &IpAddr) {
        let mut inner = self.inner.write();
        *inner.active_conns.entry(*ip).or_insert(0) += 1;
    }

    pub fn dec_conn(&self, ip: &IpAddr) {
        let mut inner = self.inner.write();
        if let Some(count) = inner.active_conns.get_mut(ip) {
            if *count > 0 {
                *count -= 1;
            }
        }
    }

    /// Periodic compaction of the disk cache.
    pub fn compact_cache(&self) {
        let dynamic_records = {
            let inner = self.inner.read();
            inner.dynamic_domain_to_ip.clone()
        };

        if let Err(e) = self.cache.compact(&dynamic_records) {
            warn!("Periodic cache compaction failed: {}", e);
        } else {
            info!(
                "Cache compaction completed ({} active mappings)",
                dynamic_records.len()
            );
        }
    }
}
