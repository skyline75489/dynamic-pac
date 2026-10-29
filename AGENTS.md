# Dynamic PAC Server

A FastAPI server with two roles:

1. **PAC file server** — serves Proxy Auto-Config files with three sources.
2. **Local HTTP CONNECT proxy** — runs alongside the PAC server on a separate port, applying the same routing rules to plain HTTPS traffic from clients that don't use PAC (CLI tools, Docker containers, etc.).

## PAC sources

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

### CONNECT proxy (`proxy_server.py`)
A standalone asyncio HTTP CONNECT proxy that runs as a sibling task to FastAPI. On each `CONNECT host:port` request, it does suffix matching against the same domain sets the PAC uses, then either:
- **DIRECT** — opens a raw TCP tunnel to the destination
- **PROXY** — tunnels through an upstream SOCKS5 or HTTP proxy extracted from the `PAC_PROXY` string

Mode is selected at startup by `PROXY_MODE`:
- `gfwlist` (default) — whitelist→DIRECT, blocklist→PROXY, unknown→DIRECT. Uses GFWList rules.
- `whitelist` — known Chinese domains→DIRECT, everything else→PROXY. Uses the dnsmasq-china-list.

Domain sets are obtained via callbacks (`get_direct_domains`, `get_proxy_domains`) configured by `app.py` from the appropriate provider.

## Endpoints

| Path | Description |
|------|-------------|
| `/proxy.pac` | Default: gfwlist/remote PAC with proxy injected |
| `/proxy.pac?source=flora` | Flora PAC (China IP hash-table) |
| `/proxy.pac?source=flora&hash_base=5003&mask_step=1` | Flora PAC with custom hash table size and mask step |
| `/proxy.pac?source=whitelist` | Whitelist PAC (Chinese domains → DIRECT) |
| `/proxy.pac?minify=true` | Any source with comments/whitespace stripped (uses rjsmin) |
| `/health` | Returns 200 with `{gfwlist_pac, flora_pac, whitelist_pac}` status; 503 if the default (gfwlist) source is not ready |
| `/rules.json` | Machine-readable rules — `{source, proxy, rules}` for gfwlist, `{direct_domains}` for whitelist, placeholder for flora |
| `/debug/proxy` | Debug snapshot of the CONNECT proxy: upstream targets, rule counts, sample route lookups |

The CONNECT proxy itself does not expose an HTTP endpoint; clients point at `LISTEN_HOST:PROXY_PORT` (default `8888`).

## Configuration (env vars)

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `PAC_PROXY` | yes | — | Injected at serving time (immediate working). e.g. `SOCKS5 1.2.3.4:1080; SOCKS 1.2.3.4:1080; PROXY 1.2.3.4:8080; DIRECT;`. Also parsed by the CONNECT proxy for upstream SOCKS5/HTTP targets. |
| `PAC_PROXY_TS_ALT` | no | — | Alternative proxy chain used by tailnet clients, e.g. `SOCKS5 100.101.1.2:1080; DIRECT;`. Empty disables tailnet-aware selection. |
| `TS_CLIENT_CIDRS` | no | `100.64.0.0/10` | Client ranges treated as tailnet clients — comma-separated (`100.64.0.0/10,10.0.0.0/8`) or a JSON list. |
| `TS_PASSTHROUGH_ENABLED` | no | — | Explicitly enable the `.ts.net` → DIRECT passthrough rule (e.g. `1`). |
| `REMOTE_PAC_URL` | yes | — | URL to fetch the upstream remote PAC from |
| `LISTEN_HOST` | no | `0.0.0.0` | FastAPI listen address |
| `LISTEN_PORT` | no | `8080` | FastAPI listen port |
| `PROXY_PORT` | no | `8888` | CONNECT proxy listen port |
| `PROXY_MODE` | no | `gfwlist` | CONNECT proxy routing mode: `gfwlist` or `whitelist` |
| `FETCH_PROXY` | no | — | Proxy for fetching remote PAC URL and APNIC data |
| `GFWLIST_CACHE_TTL` | no | `86400` | Seconds before remote PAC cache is stale |
| `REDIS_URL` | no | — | Redis for durable caching (used by all three sources) |
| `FALLBACK_PAC_PATH` | no | `fallback.pac` | Local file when remote + Redis are unavailable |
| `FLORA_FALLBACK_PATH` | no | `fallback_ip_cn.json` | Local file for China IP data when APNIC + Redis fail |
| `FLORA_CACHE_TTL` | no | `604800` | Seconds before Flora IP data cache is stale (7 days) |
| `WHITELIST_FALLBACK_PATH` | no | `fallback_domains.json` | Local file for domain list when remote + Redis fail |
| `WHITELIST_CACHE_TTL` | no | `172800` | Seconds before whitelist domain cache is stale (2 days) |

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
├── app.py                         # FastAPI server + lifespan wiring for proxy_server
├── pac_runtime.py                 # Tailnet-aware proxy selection (server-side + PAC runtime injection)
├── proxy_server.py                # HTTP CONNECT proxy (asyncio, suffix-matched routing)
├── gfwlist/
│   ├── __init__.py
│   └── provider.py                # Remote PAC fetch, Redis/fallback caching, proxy injection, rule extraction
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
├── kaniko-build.sh / kaniko-build.yaml  # Kaniko image build
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

The CONNECT proxy applies the same suffix-stripping logic to the `Host:` of each CONNECT request.

Unlike Flora (which needs `hash_base`/`mask_step`), the whitelist source has no extra query parameters — just `?source=whitelist` and optionally `&minify=true`.

## Proxy fallback (Android compatibility)

PAC clients skip proxy types they don't support. To support both desktop (SOCKS5) and Android (PROXY only):

```
SOCKS5 1.2.3.4:1080; SOCKS 1.2.3.4:1080; PROXY 1.2.3.4:8080; DIRECT;
```

The CONNECT proxy also parses this string to discover its upstream SOCKS5 and HTTP targets.

## Tailnet-aware proxy selection (PAC side)

Tailscale-specific behaviour is **opt-in**: the `.ts.net` → DIRECT
passthrough rule is only active when at least one Tailscale environment
variable is present (`PAC_PROXY_TS_ALT`, `TS_CLIENT_CIDRS` or
`TS_PASSTHROUGH_ENABLED`). With none of them set, `.ts.net` is *not*
special-cased and the PAC is served unchanged.

`pac_runtime.py` lets clients that are on a tailnet (e.g. Tailscale) use a
different upstream proxy address than the public one:

- **Server-side (exact)** — `/proxy.pac` inspects `request.client.host`; if it
  falls inside `TS_CLIENT_CIDRS`, the PAC is rendered with `PAC_PROXY_TS_ALT`
  baked into `var proxy`.
- **Client-side (dynamic)** — the served PAC carries a small runtime that
  evaluates `myIpAddress()` on every request and swaps the proxy chain for
  `PAC_PROXY_TS_ALT` when the client itself is on the tailnet. Only proxy
  chains are swapped; `DIRECT` decisions are never overridden.

Both mechanisms are no-ops when `PAC_PROXY_TS_ALT` is empty. The runtime wraps
the PAC's `FindProxyForURL` (renamed to `__dpOriginalFindProxyForURL`), so
it works for the remote/gfwlist, flora and whitelist sources alike.

With Tailscale enabled, `.ts.net` (and `ts.net`) hosts always resolve to
`DIRECT` in the whitelist PAC, the flora PAC and the CONNECT proxy.

## CI (Gitea Actions)

Workflow at `.gitea/workflows/ci.yaml`, runs on push to `master`/`main`, on
pull requests and via `workflow_dispatch`. Three jobs:

- **lint** — `ruff check`, `ruff format --check`, and `compileall`
- **test** — `python -m unittest discover -v -p 'test_*.py'`
- **docker** — `docker build` smoke check (no push)

Lint configuration lives in `pyproject.toml` (`[tool.ruff]`): line length 100,
rules `E4 E7 E9 F I UP B`, with `E501`, `B008` and `UP031` ignored (`UP031`
because `%`-formatting is intentional when emitting PAC JavaScript).

Tests live in the repo root as `test_*.py` and use `unittest`; they import
`proxy_server`, so `REMOTE_PAC_URL` is stubbed via `patch.dict`.

Run the same checks locally:

```bash
pip install -r requirements.txt ruff
ruff check . && ruff format --check .
python -m unittest discover -v -p 'test_*.py'
```

## Docker

Uses `python:3.13-slim`. Exposes port 8080 (FastAPI) — 8888 (CONNECT proxy) is
reachable but not declared — and runs as non-root `appuser`.

Build & push scripts:

- `build_and_push_image.sh` — local `podman build` + push to `localhost:5000`
- `kaniko-build.sh` / `kaniko-build.yaml` — in-cluster Kaniko build (tags with
  the short commit SHA and `:latest`, pushes to the zot registry)

## Helm

Chart at `helm/dynamic-pac/`. Key templates: `deployment.yaml`, `service.yaml`, `secret.yaml`.

Tailscale values: `pacProxyTsAlt`, `tsClientCidrs` and `tsPassthroughEnabled`
(the last one defaults to `"1"`, so the `.ts.net` → DIRECT passthrough rule
is active in Helm deployments unless it is turned off).
