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

* `--rule <domain>=<target>` : `<target>` could be:
  * `<ip>:<port>` (implicit HTTP proxy)
  * `http://<ip>:<port>` (HTTP proxy)
  * `socks5://<ip>:<port>` (SOCKS5 proxy, remote DNS resolution)
  * `socks5h://<ip>:<port>` (alias of `socks5`)
  * `direct` (direct connect)
  * `reject` (drop / terminate connection)
  
  Multiple rules can be provided. Rules are evaluated in order; the first match is used.
  By default, `<domain>` matches subdomains as well (e.g. `example.com` matches `example.com`, `a.example.com`, and `a.b.example.com`).
  Prefixes supported:
  * `*` : wildcard subdomains only. E.g. `*.example.com` matches `a.example.com` and `b.a.example.com` but NOT `example.com` itself.
  * `-` : main domain only. E.g. `-.example.com` matches `example.com` only, NOT `a.example.com`.
  * An implicit `*=reject` fallback rule is always used at the end. At least 1 rule must be provided.

* `--fakeip-range <cidr>` : (Optional) The fake IP CIDR range. Defaults to `198.18.0.0/15`.
* `--fakeip <domain>=<ip>` : (Optional) Pre-assign fixed/static fake IP to domains (exact domain only). Example: `--fakeip google.com=198.18.0.2`. Static fake IPs take precedence over dynamic allocations.
* `--listen [<ip>:]<port>` : (Optional) TPROXY listen address. Defaults to `7080`.
* `--listen-dns [<ip>:]<port>` : (Optional) DNS server listen address. Defaults to `7053`.
* `--cache <path>` : (Optional) Disk fake IP cache file path. Defaults to `/tmp/fitproxy_fakeip`.
* `-c, --config <path>` : (Optional) Path to JSON config file (if it exists). Defaults to `/etc/fitproxy.json`. CLI flags override config file options.
* `--no-network-setup` : (Optional) Disable automatic `nftables` and `ip rule`/`ip route` setup (useful in non-root or container testing environments).
* `--table-id <id>` : (Optional) Policy routing table ID. Defaults to `7080`.
* `--fwmark <mark>` : (Optional) Firewall mark. Defaults to `32768` (0x8000).

## Config File Format (`/etc/fitproxy.json`)

```json
{
  "rules": [
    "example.com=127.0.0.1:1080",
    "ipinfo.io=socks5://127.0.0.1:1080",
    "local.lan=direct"
  ],
  "fakeip_range": "198.18.0.0/15",
  "fakeip": {
    "google.com": "198.18.0.2"
  },
  "listen": "7080",
  "listen_dns": "7053",
  "cache": "/tmp/fitproxy_fakeip",
  "setup_network": true,
  "table_id": 100,
  "fwmark": 1
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

### GitHub Actions Release

Pushing any tag starting with `v*` (e.g. `v0.1.0`) triggers `.github/workflows/release.yml`, building and publishing statically linked musl binaries to GitHub Releases:

- `fitproxy-x86_64-unknown-linux-musl`
- `fitproxy-aarch64-unknown-linux-musl`