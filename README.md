# fitproxy

A simple Linux fake ip + TPROXY DNS server + proxy software in Rust. Linux only. It includes:

- **DNS Server**: Accepts DNS requests for specified domains, allocating and returning a fake IP from the configured CIDR range. Queries for non-matching/rejected domains or IPv6 `AAAA` records return `NODATA` (empty answer) immediately so clients fail fast and fall back to IPv4.
- **TPROXY Proxy**: Listens for TCP connections redirected by `nftables` TPROXY, identifies the original destination fake IP, maps it back to the original domain name, and forwards the request according to matching rules: direct connection, HTTP proxy, SOCKS5 proxy, or reject (close connection).
- **Append-Only Disk Cache**: Stores fake IP assignments in a high-performance append-only JSONL log format, automatically cleaned, deduplicated, and compacted on startup and periodically during execution.
- **Automatic Idempotent Network Setup**: Configures required policy routing (`ip rule`, `ip route`) and `nftables` TPROXY rules (`table inet fitproxy`) automatically on start, and cleans them up gracefully on exit.

## Example Usage

```bash
fitproxy \
  --rule example.com=127.0.0.1:1080 \
  --rule ipinfo.io=socks5://127.0.0.1:1080
```

## Flags

* `--rule <pattern>=<target>` : `<pattern>` can be a domain name or an IPv4/IPv6 CIDR (e.g. `0.0.0.0/0`, `::/0`, `192.168.0.0/16`, `10.0.0.1`). `<target>` could be:
  * `<ip>:<port>` (implicit HTTP proxy, TCP only)
  * `http://<ip>:<port>` (HTTP proxy, TCP only)
  * `socks5://<ip>:<port>` (SOCKS5 proxy; TCP + UDP ASSOCIATE supported)
  * `socks5://<ip>:<port>?udp=0` (SOCKS5 proxy without UDP support; UDP traffic will be rejected directly)
  * `socks5h://<ip>:<port>` (alias of `socks5`)
  * `direct` (direct connect, TCP + UDP supported)
  * `reject` (drop / terminate connection)
  
  Multiple rules can be provided. Rules are evaluated in order; the first match is used.
  * For domains: by default, `<domain>` matches subdomains as well (e.g. `example.com` matches `example.com`, `a.example.com`, and `a.b.example.com`).
    * `*` : wildcard subdomains only. E.g. `*.example.com` matches `a.example.com` but NOT `example.com` itself.
    * `-` : main domain only. E.g. `-.example.com` matches `example.com` only, NOT `a.example.com`.
  * For IP CIDRs: e.g. `0.0.0.0/0=direct`, `::/0=socks5://127.0.0.1:1080`, or `192.168.0.0/16=reject`. When the TPROXY listen port receives a request whose destination IP is not a fake IP, it matches against IP rules (with longest-prefix match precedence). If accepted by an IP rule (and not matched by an IP reject rule), it forwards the original request directly or via proxy.
  * For UDP TPROXY: supports `direct` and `socks5` proxy targets (via SOCKS5 UDP ASSOCIATE). If a SOCKS5 target specifies `?udp=0` (or `?udp=false`), UDP requests matching that rule are rejected directly. HTTP proxy targets do not support UDP and will reject UDP requests.
  * Allowed IP CIDRs are automatically included in `nftables` TPROXY `ip daddr` / `ip6 daddr` sets matching both `{ tcp, udp }`.
  * An implicit fallback reject rule is always used at the end. At least 1 rule must be provided.

* `--interface <interfaces>` : (Optional) Comma-separated list of network interfaces (e.g. `eth0` or `eth0,eth1`). If provided, the nftables prerouting TPROXY rule will only match traffic received on those interface(s) using `iifname { "eth0" }`.
* `--egress-mark <mark>` : (Optional) Firewall mark bitmask set on fitproxy egress sockets to prevent routing loops (e.g. `0x10000/0x10000`). Packets with this mark are excluded in nftables TPROXY rules. Defaults to `0x10000/0x10000`.
* `--fakeip-range <cidr>` : (Optional) The fake IP CIDR range (supports IPv4 e.g. `198.18.0.0/15` or IPv6 e.g. `fc00::/18`). Defaults to `198.18.0.0/15`.
* `--fakeip <domain>=<ip>` : (Optional) Pre-assign fixed/static fake IP to domains (exact domain only, IPv4 or IPv6). Example: `--fakeip google.com=198.18.0.2`. Static fake IPs take precedence over dynamic allocations.
* `--listen [<ip>:]<port>` : (Optional) TPROXY listen address. Defaults to `7080`.
* `--listen-dns [<ip>:]<port>` : (Optional) DNS server listen address. Defaults to `7053`.
* `--cache <path>` : (Optional) Disk fake IP cache file path. Defaults to `/tmp/fitproxy_fakeip`.
* `-c, --config <path>` : (Optional) Path to JSON config file (if it exists). Defaults to `/etc/fitproxy.json`. CLI flags override config file options.
* `--no-network-setup` : (Optional) Disable automatic `nftables` and `ip rule`/`ip route` setup (useful in non-root or container testing environments).
* `--table-id <id>` : (Optional) Policy routing table ID. Sets up two routing tables: `<id>` (prio 3 for marked traffic) and `<id> + 1` (prio 4 link route). Defaults to `7080`.
* `--fwmark <mark>` : (Optional) Firewall mark in format `"mark"` or `"mark/bitmask"` (e.g. `0x8000/0x8000`). Defaults to `"0x8000/0x8000"`.

## Config File Format (`/etc/fitproxy.json`)

```json
{
  "rules": [
    "example.com=127.0.0.1:1080",
    "ipinfo.io=socks5://127.0.0.1:1080",
    "0.0.0.0/0=direct",
    "192.168.0.0/16=reject"
  ],
  "interface": ["eth0"],
  "egress_mark": "0x10000/0x10000",
  "fakeip_range": "198.18.0.0/15",
  "fakeip": {
    "google.com": "198.18.0.2"
  },
  "listen": "7080",
  "listen_dns": "7053",
  "cache": "/tmp/fitproxy_fakeip",
  "setup_network": true,
  "table_id": 7080,
  "fwmark": "0x8000/0x8000"
}
```

## Disk Cache Specification

The disk cache stores fake IP assignments in an append-only JSON Lines (`jsonl`) log:
```json
{"domain":"example.com","ip":"198.18.0.2","ts":1712000000}
```

- **Append-only**: When a domain is dynamically allocated an IP, a single record is appended without rewriting the file ($O(1)$ disk write).
- **Startup Cleanup & Deduplication**: On startup, existing entries are validated against active rules, fake IP range, and static assignments. Stale entries are pruned, and the file is immediately compacted and deduplicated.
- **Compaction**: Periodic background compaction and graceful shutdown rewrite active mappings to a temporary file with atomic `rename(2)` for crash safety.

## Building & Releases

### Build Locally

```bash
# Build native debug/release
cargo build --release

# Build both Linux musl targets into dist/
./build.sh

# Or build a specific target
./build.sh x86_64-unknown-linux-musl
./build.sh aarch64-unknown-linux-musl
```

### Docker

#### Build Docker Image Locally

```bash
docker build -t fitproxy .
```

#### Run with Docker

```bash
# Run with host networking and net admin capability (needed for TPROXY and routing)
docker run -d \
  --name fitproxy \
  --network host \
  --cap-add=NET_ADMIN \
  -v /etc/fitproxy.json:/etc/fitproxy.json:ro \
  ghcr.io/<owner>/fitproxy:latest \
  -c /etc/fitproxy.json
```

### GitHub Actions Release

Pushing any tag starting with `v*` (e.g. `v0.1.0`) triggers `.github/workflows/release.yml`:

1. **GitHub Releases**: Builds and publishes statically linked musl binaries with SHA256 checksums:
   - `fitproxy-x86_64-unknown-linux-musl`
   - `fitproxy-aarch64-unknown-linux-musl`
2. **GitHub Packages**: Builds and publishes multi-arch container images (`linux/amd64`, `linux/arm64`) to GitHub Container Registry:
   - `ghcr.io/<owner>/fitproxy:<tag>`
   - `ghcr.io/<owner>/fitproxy:latest`
