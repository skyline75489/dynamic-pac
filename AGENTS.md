# Dynamic PAC Server

A FastAPI server that serves PAC (Proxy Auto-Config) files with three sources:

- **Remote PAC** (default): fetches a remote gfwlist-style PAC, injects the proxy at serving time
- **Flora PAC** (`?source=flora`): generates a hash-table-based PAC from China IP ranges (China IPs → DIRECT, rest → proxy)
- **Whitelist PAC** (`?source=whitelist`): generates a domain-based PAC from dnsmasq-china-list (Chinese domains → DIRECT, rest → proxy)

## Architecture

### Remote PAC source chain
remote URL → Redis → local fallback file. Each layer is tried in order. Proxy injection happens at serving time via regex on `var proxy = '...'` — changing `PAC_PROXY` takes effect immediately.

### Flora PAC source chain
Redis → APNIC → local fallback file (`fallback_ip_cn.json`). The expensive APNIC fetch (~30s) runs once; results are cached in Redis (7d TTL) and the fallback file. On each request, the cached IP data is fragmented and hashed with the requested `hash_base`/`mask_step`, then the proxy is injected via placeholder replacement.

### Whitelist PAC source chain
Redis → dnsmasq-china-list → local fallback file (`fallback_domains.json`). Fetches a curated list of Chinese domains, serializes as a JSON object in the PAC. Domain matching uses suffix-tree traversal with `hasOwnProperty` for O(1) lookups. `.cn` domains short-circuit to DIRECT without checking the whitelist.

All sources serve stale data during background refreshes — requests never block.

## Endpoints

| Path | Description |
|------|-------------|
| `/proxy.pac` | Default: gfwlist/remote PAC with proxy injected |
| `/proxy.pac?source=flora` | Flora PAC (China IP hash-table) |
| `/proxy.pac?source=flora&hash_base=5003&mask_step=1` | Flora PAC with custom hash table size and mask step |
| `/proxy.pac?source=whitelist` | Whitelist PAC (Chinese domains → DIRECT) |
| `/proxy.pac?minify=true` | Any source with comments/whitespace stripped (uses rjsmin) |
| `/health` | Returns 200 with `{gfwlist_pac, flora_pac, whitelist_pac}` status |

## Configuration (env vars)

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `PAC_PROXY` | yes | — | Injected at serving time (immediate working). e.g. `SOCKS5 1.2.3.4:1080; SOCKS 1.2.3.4:1080; PROXY 1.2.3.4:8080; DIRECT;` |
| `REMOTE_PAC_URL` | yes | — | URL to fetch the upstream remote PAC from |
| `LISTEN_HOST` | no | `0.0.0.0` | |
| `LISTEN_PORT` | no | `8080` | |
| `FETCH_PROXY` | no | — | Proxy for fetching remote PAC URL and APNIC data |
| `GFWLIST_CACHE_TTL` | no | `86400` | Seconds before remote PAC cache is stale |
| `REDIS_URL` | no | — | Redis for durable caching (used by both remote and Flora) |
| `FALLBACK_PAC_PATH` | no | `fallback.pac` | Local file when remote + Redis are unavailable |
| `FLORA_FALLBACK_PATH` | no | `fallback_ip_cn.json` | Local file for China IP data when APNIC + Redis fail |
| `FLORA_CACHE_TTL` | no | `604800` | Seconds before Flora IP data cache is stale (7 days) |
| `WHITELIST_FALLBACK_PATH` | no | `fallback_domains.json` | Local file for domain list when remote + Redis fail |
| `WHITELIST_CACHE_TTL` | no | `86400` | Seconds before whitelist domain cache is stale |

## Query parameters

These apply to `/proxy.pac` regardless of `source`.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `source` | string | `remote` | PAC source: `remote` (gfwlist), `flora` (China IP hash-table), or `whitelist` (Chinese domains) |
| `minify` | bool | `false` | Strip comments and whitespace from the resulting PAC |

### Flora-specific parameters

| Param | Default | Range | Description |
|-------|---------|-------|-------------|
| `hash_base` | 3011 | 1001–99999 | Hash table size — larger = faster matching, bigger file |
| `mask_step` | 2 | 1–8 | Network mask fragmentation step — smaller = more precise |

LRU caches up to 32 unique (hash_base, mask_step) combinations.

## Project structure

```
├── app.py                         # FastAPI server
├── gfwlist/
│   ├── __init__.py
│   └── provider.py                # Remote PAC fetch, Redis/fallback caching, proxy injection
├── flora/
│   ├── __init__.py
│   ├── ip_data.py                 # APNIC fetch + network merging
│   ├── network_ops.py             # Fragmentation + hashing
│   ├── pac_generator.py           # PAC JS generation with placeholder
│   └── provider.py                # Redis/fallback caching + proxy injection
├── whitelist/
│   ├── __init__.py
│   ├── fetcher.py                 # dnsmasq-china-list fetch + parse
│   ├── pac_generator.py           # Domain whitelist PAC generation
│   └── provider.py                # Redis/fallback caching + proxy injection
├── fallback.pac                   # Remote PAC offline fallback
├── fallback_ip_cn.json            # China IP data offline fallback
├── fallback_domains.json          # Domain whitelist offline fallback
├── Dockerfile
├── requirements.txt
└── helm/dynamic-pac/              # Helm chart (templates + values)
```

## Whitelist PAC matching logic

The whitelist PAC uses a suffix-tree approach for domain matching:

1. **Plain hostnames** (no dots) → DIRECT
2. **IPv4 addresses** → check private range (10.x, 127.x, 172.16.x, 192.168.x) → DIRECT if private, else PROXY
3. **IPv6 addresses** → check private range (::/127, fe80::/64, fec0::/48) → DIRECT if private, else PROXY
4. **`.cn` domains** → DIRECT immediately (short-circuit)
5. **Other domains** → strip subdomains left-to-right, check each suffix against the whitelist JSON object via `hasOwnProperty`. First match wins; no match → PROXY

The domain list comes from [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list), the same source used by the original [gfw_domain_whitelist](https://github.com/R0uter/gfw_domain_whitelist) project.

Unlike Flora (which needs `hash_base`/`mask_step`), the whitelist source has no extra query parameters — just `?source=whitelist` and optionally `&minify=true`.

## Proxy fallback (Android compatibility)

PAC clients skip proxy types they don't support. To support both desktop (SOCKS5) and Android (PROXY only):

```
SOCKS5 1.2.3.4:1080; SOCKS 1.2.3.4:1080; PROXY 1.2.3.4:8080; DIRECT;
```

## Docker

Uses `mcr.microsoft.com/azurelinux/base/python:3.12`. Exposes port 8080, runs as non-root `appuser`.

## Helm

Chart at `helm/dynamic-pac/`. Key templates: `deployment.yaml`, `service.yaml`, `secret.yaml`.
