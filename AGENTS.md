# Dynamic PAC Server

A FastAPI server that fetches a remote PAC file, injects a proxy setting, and serves it.

## Architecture

- **Source chain**: remote URL → Redis → local fallback file. Each layer is tried in order; the first to succeed populates an in-memory cache. The cache stores the raw (uninjected) PAC content — proxy injection happens at serving time, so changing `PAC_PROXY` takes effect immediately without waiting for cache expiration.
- **Cache**: in-memory with configurable TTL (`CACHE_TTL`, default 86400s). When stale, a background task refreshes from remote — serving never blocks on refresh.
- **Proxy injection**: on every request, the PAC `var proxy = '...'` line is replaced via regex with the current value of `PAC_PROXY`.

## Endpoints

| Path | Description |
|------|-------------|
| `/proxy.pac` | Returns the PAC file with injected proxy |
| `/health` | Returns 200 if cache is populated, 503 if empty |

## Configuration (env vars)

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `PAC_PROXY` | yes | — | Injected into the PAC file at serving time (changes take effect immediately, no cache invalidation needed). Must be a valid PAC proxy string (e.g., `SOCKS5 1.2.3.4:1080; SOCKS 1.2.3.4:1080; PROXY 1.2.3.4:8080; DIRECT;`). Clients that don't support one type fall through to the next. |
| `REMOTE_PAC_URL` | yes | — | URL to fetch the upstream PAC file from |
| `LISTEN_HOST` | no | `0.0.0.0` | |
| `LISTEN_PORT` | no | `8080` | |
| `FETCH_PROXY` | no | — | Proxy used only when fetching the remote PAC URL |
| `CACHE_TTL` | no | `86400` | Seconds before cache is considered stale |
| `REDIS_URL` | no | — | If set, cache is persisted to Redis (optional) |
| `FALLBACK_PAC_PATH` | no | `fallback.pac` | Local file used when remote and Redis are unavailable |

## PAC file format

The PAC file is standard JavaScript with `FindProxyForURL(url, host)`. The template (demo.pac / fallback.pac) uses a rules array:

```js
var rules = [
    [                     // Rule 0
        ["domain1.com"],  //   [0] = DIRECT list
        ["domain2.com"]   //   [1] = PROXY list
    ],
    // ... more rules
];
```

Each rule is `[directList, proxyList]`. A host matching the first list goes DIRECT; matching the second goes through the proxy. Rules are checked in order; first match wins. No match defaults to DIRECT.

## Proxy fallback (Android compatibility)

PAC clients skip proxy types they don't support. To support both desktop (SOCKS5) and Android (PROXY only), include both in the fallback chain:

```
SOCKS5 1.2.3.4:1080; SOCKS 1.2.3.4:1080; PROXY 1.2.3.4:8080; DIRECT;
```

Desktop uses SOCKS5; Android falls through to PROXY. No code changes needed — just set `PAC_PROXY`.

## Docker

The Dockerfile uses `mcr.microsoft.com/azurelinux/base/python:3.12`. Exposes port 8080, runs as non-root `appuser`.

## Helm

The Helm chart is at `helm/dynamic-pac/`. Key templates: `deployment.yaml`, `service.yaml`, `secret.yaml`.
