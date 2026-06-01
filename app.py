import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response, Query

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
REDIS_URL = os.getenv("REDIS_URL", "").strip()

if not PAC_PROXY:
    raise RuntimeError("PAC_PROXY environment variable is required")

logger = logging.getLogger("dynamic-pac.main")

# ---------------------------------------------------------------------------
# GFWList / remote PAC provider
# ---------------------------------------------------------------------------
from gfwlist.provider import (  # noqa: E402
    seed_cache,
    get_pac_content as get_gfwlist_pac,
    get_rules as get_gfwlist_rules,
    set_redis as set_gfwlist_redis,
    is_ready as is_gfwlist_ready,
)

# ---------------------------------------------------------------------------
# Flora PAC provider
# ---------------------------------------------------------------------------
from flora.provider import (  # noqa: E402
    fetch_and_cache_ip_data,
    get_pac_content,
    set_redis as set_flora_redis,
    is_ready as is_flora_ready,
)

# ---------------------------------------------------------------------------
# Whitelist PAC provider
# ---------------------------------------------------------------------------
from whitelist.provider import (  # noqa: E402
    fetch_and_cache_domain_data,
    get_pac_content as get_whitelist_pac,
    get_domains as get_whitelist_domains,
    set_redis as set_whitelist_redis,
    is_ready as is_whitelist_ready,
)

# ---------------------------------------------------------------------------
# Proxy server
# ---------------------------------------------------------------------------
import proxy_server  # noqa: E402

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
    source: str = Query("remote", description="PAC source: 'remote' (gfwlist), 'flora' (China IPs), or 'whitelist' (Chinese domains)"),
    hash_base: int = Query(3011, ge=1001, le=99999, description="Hash table size for Flora PAC (default: 3011)"),
    mask_step: int = Query(2, ge=1, le=8, description="Network mask fragmentation step for Flora PAC (default: 2)"),
    minify: bool = Query(False, description="Minify the resulting PAC by stripping comments and whitespace"),
):
    if source == "flora":
        if not is_flora_ready():
            return Response(
                status_code=503,
                content="Flora PAC not yet ready (still fetching APNIC data)",
            )

        content = get_pac_content(hash_base, mask_step, PAC_PROXY)
        if content is None:
            return Response(status_code=503, content="Flora PAC unavailable")

        if minify:
            content = _minify_js(content)

        return Response(
            content=content,
            media_type="text/plain",  # text/plain so browsers display inline instead of downloading; PAC exec engines ignore MIME type
        )

    if source == "whitelist":
        if not is_whitelist_ready():
            return Response(
                status_code=503,
                content="Whitelist PAC not yet ready (still fetching domain list)",
            )

        content = get_whitelist_pac(PAC_PROXY)
        if content is None:
            return Response(status_code=503, content="Whitelist PAC unavailable")

        if minify:
            content = _minify_js(content)

        return Response(
            content=content,
            media_type="text/plain",  # text/plain so browsers display inline instead of downloading; PAC exec engines ignore MIME type
        )

    # Default: gfwlist / remote PAC
    if not is_gfwlist_ready():
        return Response(
            status_code=503,
            content="Remote PAC not yet ready",
        )

    content = get_gfwlist_pac(PAC_PROXY)
    if content is None:
        return Response(status_code=503, content="Remote PAC unavailable")

    if minify:
        content = _minify_js(content)

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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT, log_config=None)
