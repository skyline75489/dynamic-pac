import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, Request, Response

import proxy_server
from flora.provider import (
    fetch_and_cache_ip_data,
    get_pac_content,
)
from flora.provider import (
    is_ready as is_flora_ready,
)
from flora.provider import (
    set_redis as set_flora_redis,
)
from gfwlist.provider import (
    get_pac_content as get_gfwlist_pac,
)
from gfwlist.provider import (
    get_rules as get_gfwlist_rules,
)
from gfwlist.provider import (
    is_ready as is_gfwlist_ready,
)
from gfwlist.provider import (
    seed_cache,
)
from gfwlist.provider import (
    set_redis as set_gfwlist_redis,
)
from pac_runtime import (
    apply_alt_proxy_runtime,
    get_alt_proxy,
    get_ts_cidrs,
    select_proxy_chain,
    ts_passthrough_enabled,
)
from whitelist.provider import (
    fetch_and_cache_domain_data,
)
from whitelist.provider import (
    get_domains as get_whitelist_domains,
)
from whitelist.provider import (
    get_pac_content as get_whitelist_pac,
)
from whitelist.provider import (
    is_ready as is_whitelist_ready,
)
from whitelist.provider import (
    set_redis as set_whitelist_redis,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
PROXY_PORT = int(os.getenv("PROXY_PORT", "8888"))
PAC_PROXY = os.getenv("PAC_PROXY", "").strip()
PROXY_MODE = os.getenv("PROXY_MODE", "gfwlist").strip().lower()
REDIS_URL = os.getenv("REDIS_URL", "").strip()

if not PAC_PROXY:
    raise RuntimeError("PAC_PROXY environment variable is required")

logger = logging.getLogger("dynamic-pac.main")

# ---------------------------------------------------------------------------
# GFWList / remote PAC provider
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Proxy server
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Flora PAC provider
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Tailnet-aware proxy selection (PAC side)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Whitelist PAC provider
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Redis (optional)
# ---------------------------------------------------------------------------
_redis = None
if REDIS_URL:
    import redis.asyncio as aioredis

    _redis = aioredis.from_url(REDIS_URL)
    set_gfwlist_redis(_redis)
    set_flora_redis(_redis)
    set_whitelist_redis(_redis)
    logger.info("Redis configured: %s", REDIS_URL)


def _minify_js(content: str) -> str:
    import rjsmin

    return rjsmin.jsmin(content)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # Seed the gfwlist cache (blocks startup — the default source)
    await seed_cache()

    # Fetch Flora IP data and whitelist domains in background
    asyncio.create_task(fetch_and_cache_ip_data())
    asyncio.create_task(fetch_and_cache_domain_data())

    # Configure the proxy server's routing mode
    if PROXY_MODE == "whitelist":
        # Chinese domains → DIRECT, everything else → PROXY
        proxy_server.configure(
            get_direct_domains=lambda: (
                set(d) if (d := get_whitelist_domains()) is not None else None
            ),
            get_proxy_domains=None,
            default_route="PROXY",
        )
        logger.info("Proxy mode: whitelist (Chinese domains direct, rest proxy)")
    else:
        # GFWList mode: whitelisted domains → DIRECT, blocklisted → PROXY,
        # unknown → DIRECT
        proxy_server.configure(
            get_direct_domains=proxy_server.get_gfwlist_direct_domains,
            get_proxy_domains=proxy_server.get_gfwlist_proxy_domains,
            default_route="DIRECT",
        )
        logger.info("Proxy mode: gfwlist (whitelist direct, blocklist proxy)")

    # Start the CONNECT proxy server
    proxy_ready = asyncio.Event()
    proxy_task = asyncio.create_task(
        proxy_server.start(
            host="0.0.0.0",
            port=PROXY_PORT,
            ready_event=proxy_ready,
        ),
    )
    await proxy_ready.wait()

    logger.info("CONNECT proxy ready on port %d", PROXY_PORT)

    yield

    # Shutdown: cancel proxy task
    proxy_task.cancel()
    try:
        await proxy_task
    except asyncio.CancelledError:
        pass

    if _redis is not None:
        await _redis.aclose()


app = FastAPI(lifespan=_lifespan)


@app.get("/proxy.pac")
async def proxy_pac(
    request: Request,
    source: str = Query(
        "remote",
        description="PAC source: 'remote' (gfwlist), 'flora' (China IPs), or 'whitelist' (Chinese domains)",
    ),
    hash_base: int = Query(
        3011, ge=1001, le=99999, description="Hash table size for Flora PAC (default: 3011)"
    ),
    mask_step: int = Query(
        2, ge=1, le=8, description="Network mask fragmentation step for Flora PAC (default: 2)"
    ),
    minify: bool = Query(
        False, description="Minify the resulting PAC by stripping comments and whitespace"
    ),
):
    # Tailnet-aware proxy selection: clients inside the tailnet CIDRs get
    # the alternative proxy chain (PAC_PROXY_TS_ALT) baked into the PAC.
    alt_proxy = get_alt_proxy()
    client_ip = request.client.host if request.client else None
    proxy_chain, server_tailnet = select_proxy_chain(client_ip, PAC_PROXY, alt_proxy)

    if source == "flora":
        if not is_flora_ready():
            return Response(
                status_code=503,
                content="Flora PAC not yet ready (still fetching APNIC data)",
            )

        content = get_pac_content(hash_base, mask_step, proxy_chain)
        if content is None:
            return Response(status_code=503, content="Flora PAC unavailable")
    elif source == "whitelist":
        if not is_whitelist_ready():
            return Response(
                status_code=503,
                content="Whitelist PAC not yet ready (still fetching domain list)",
            )

        content = get_whitelist_pac(proxy_chain)
        if content is None:
            return Response(status_code=503, content="Whitelist PAC unavailable")
    else:
        # Default: gfwlist / remote PAC
        if not is_gfwlist_ready():
            return Response(
                status_code=503,
                content="Remote PAC not yet ready",
            )

        content = get_gfwlist_pac(proxy_chain)
        if content is None:
            return Response(status_code=503, content="Remote PAC unavailable")

    if minify:
        content = _minify_js(content)

    # Client-side runtime: switch to the alternative chain when the
    # requesting client itself is on the tailnet (myIpAddress()).
    content = apply_alt_proxy_runtime(content, alt_proxy, server_tailnet)

    return Response(
        content=content,
        media_type="text/plain",  # text/plain so browsers display inline instead of downloading; PAC exec engines ignore MIME type
    )


@app.get("/health")
async def health():
    gfwlist_ok = is_gfwlist_ready()
    flora_ok = is_flora_ready()
    whitelist_ok = is_whitelist_ready()

    if not gfwlist_ok:
        return Response(
            status_code=503,
            content={
                "status": "degraded",
                "gfwlist_pac": False,
                "flora_pac": flora_ok,
                "whitelist_pac": whitelist_ok,
            },
        )
    return {
        "status": "ok",
        "gfwlist_pac": True,
        "flora_pac": flora_ok,
        "whitelist_pac": whitelist_ok,
    }


@app.get("/rules.json")
async def get_rules(
    source: str = Query(
        "remote",
        description="Rule source: 'remote' (gfwlist), 'whitelist' (Chinese domains), or 'flora' (China IPs)",
    ),
):
    if source == "whitelist":
        domains = get_whitelist_domains()
        if domains is None:
            return Response(
                status_code=503,
                content={"error": "Whitelist data not yet ready"},
            )
        return {
            "source": "whitelist",
            "proxy": PAC_PROXY,
            "direct_domains": domains,
            "type": "whitelist",
        }

    if source == "flora":
        # Flora uses IP ranges, not domains — return a placeholder for now
        return {
            "source": "flora",
            "proxy": PAC_PROXY,
            "type": "ip_range",
            "note": "Flora uses China IP ranges, not domain lists",
        }

    # Default: remote/gfwlist
    data = get_gfwlist_rules()
    if data is None:
        return Response(
            status_code=503,
            content={"error": "Remote PAC rules not yet ready"},
        )

    # Normalize the proxy string to just the routing part
    proxy_val = PAC_PROXY or data["proxy"]

    return {
        "source": "remote",
        "proxy": proxy_val,
        "rules": data["rules"],
        "type": "gfwlist",
    }


@app.get("/debug/proxy")
async def debug_proxy():
    """Debug endpoint to inspect proxy server state."""
    socks5_list = proxy_server._upstream.get("socks5", [])
    http_list = proxy_server._upstream.get("http", [])
    return {
        "upstream_socks5": [{"host": h, "port": p} for h, p in socks5_list],
        "upstream_http": [{"host": h, "port": p} for h, p in http_list],
        # Backwards-compat: first SOCKS5 entry (None if none configured)
        "upstream_host": socks5_list[0][0] if socks5_list else None,
        "upstream_port": socks5_list[0][1] if socks5_list else None,
        "rules_loaded": proxy_server._rules_loaded,
        "direct_count": len(proxy_server._direct_set),
        "proxy_count": len(proxy_server._proxy_set),
        "default_route": proxy_server._default_route,
        "route_google": await proxy_server.get_route("google.com"),
        "route_k8s": await proxy_server.get_route("homeassistant.homeassistant.svc.cluster.local"),
        "tailnet": {
            "passthrough_enabled": ts_passthrough_enabled(),
            "alt_proxy": get_alt_proxy(),
            "client_cidrs": [str(net) for net in get_ts_cidrs()],
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT, log_config=None)
