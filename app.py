import asyncio
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Response

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
PAC_PROXY = os.getenv("PAC_PROXY", "").strip()
REMOTE_PAC_URL = os.getenv("REMOTE_PAC_URL", "").strip()
FETCH_PROXY = os.getenv("FETCH_PROXY", "").strip()
CACHE_TTL = int(os.getenv("CACHE_TTL", "86400"))
REDIS_URL = os.getenv("REDIS_URL", "").strip()
FALLBACK_PAC_PATH = os.getenv("FALLBACK_PAC_PATH", "fallback.pac").strip()

if not PAC_PROXY:
    raise RuntimeError("PAC_PROXY environment variable is required")
if not REMOTE_PAC_URL:
    raise RuntimeError("REMOTE_PAC_URL environment variable is required")

logger = logging.getLogger("dynamic-pac")

# ---------------------------------------------------------------------------
# Redis (optional)
# ---------------------------------------------------------------------------
_redis = None
if REDIS_URL:
    import redis.asyncio as aioredis

    _redis = aioredis.from_url(REDIS_URL)
    logger.info("Redis configured: %s", REDIS_URL)

REDIS_CONTENT_KEY = "dynamic-pac:content"

# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------
_cached_pac: str | None = None
_cached_at: float = 0.0
_refresh_lock = asyncio.Lock()

# ---------------------------------------------------------------------------
# Proxy injection
# ---------------------------------------------------------------------------
PROXY_RE = re.compile(r"var\s+proxy\s*=\s*'[^']*'\s*;")

def _inject_proxy(content: str) -> str:
    new = PROXY_RE.sub(lambda _: f"var proxy = '{PAC_PROXY}';", content, count=1)
    if new == content:
        logger.warning("proxy var not found in PAC — prepending")
        new = f"var proxy = '{PAC_PROXY}';\n{content}"
    return new

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------
def _build_client() -> httpx.AsyncClient:
    kwargs: dict = {"timeout": 30.0}
    if FETCH_PROXY:
        kwargs["proxy"] = FETCH_PROXY
    return httpx.AsyncClient(**kwargs)


async def _fetch_remote() -> str | None:
    try:
        async with _build_client() as client:
            resp = await client.get(REMOTE_PAC_URL)
            resp.raise_for_status()
            logger.info("Fetched remote PAC (%d bytes)", len(resp.text))
            return resp.text
    except Exception:
        logger.exception("Remote fetch failed")
        return None


async def _read_redis() -> str | None:
    if _redis is None:
        return None
    try:
        data = await _redis.get(REDIS_CONTENT_KEY)
        if data:
            logger.info("Loaded PAC from Redis (%d bytes)", len(data))
            return data.decode("utf-8")
        logger.info("Redis key not found")
    except Exception:
        logger.exception("Redis read failed")
    return None


async def _write_redis(content: str) -> None:
    if _redis is None:
        return
    try:
        await _redis.set(REDIS_CONTENT_KEY, content, ex=CACHE_TTL)
        logger.info("Written to Redis (TTL=%ds)", CACHE_TTL)
    except Exception:
        logger.exception("Redis write failed")


def _load_fallback() -> str | None:
    path = Path(FALLBACK_PAC_PATH)
    if not path.is_file():
        logger.warning("Fallback file not found: %s", FALLBACK_PAC_PATH)
        return None
    try:
        content = path.read_text()
        logger.info("Loaded fallback PAC (%d bytes)", len(content))
        return content
    except Exception:
        logger.exception("Fallback load failed")
        return None

# ---------------------------------------------------------------------------
# Cache logic
# ---------------------------------------------------------------------------
async def _seed_cache() -> None:
    global _cached_pac, _cached_at

    content = await _fetch_remote()
    if content is not None:
        _cached_pac, _cached_at = content, time.monotonic()
        await _write_redis(content)
        logger.info("Cache seeded from remote")
        return

    content = await _read_redis()
    if content is not None:
        _cached_pac, _cached_at = content, time.monotonic()
        logger.info("Cache seeded from Redis")
        return

    content = _load_fallback()
    if content is not None:
        _cached_pac, _cached_at = content, time.monotonic()
        logger.info("Cache seeded from fallback")
        return

    logger.error("All sources exhausted — starting empty")


def _is_stale() -> bool:
    if _cached_pac is None:
        return True
    return (time.monotonic() - _cached_at) >= CACHE_TTL


def _trigger_refresh() -> None:
    if not _refresh_lock.locked():
        asyncio.create_task(_do_refresh())


async def _do_refresh() -> None:
    global _cached_pac, _cached_at
    async with _refresh_lock:
        logger.info("Cache refresh started")

        content = await _fetch_remote()
        if content is not None:
            _cached_pac, _cached_at = content, time.monotonic()
            await _write_redis(content)
            logger.info("Cache refreshed from remote")
            return

        content = await _read_redis()
        if content is not None:
            _cached_pac, _cached_at = content, time.monotonic()
            logger.info("Cache refreshed from Redis")
            return

        content = _load_fallback()
        if content is not None:
            _cached_pac, _cached_at = content, time.monotonic()
            logger.warning("Remote and Redis failed — using local fallback")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
@asynccontextmanager
async def _lifespan(_app: FastAPI):
    await _seed_cache()
    yield
    if _redis is not None:
        await _redis.aclose()

app = FastAPI(lifespan=_lifespan)


@app.get("/proxy.pac")
async def proxy_pac():
    if _is_stale():
        _trigger_refresh()

    if _cached_pac is None:
        return Response(status_code=503, content="No PAC data available")

    return Response(
        content=_inject_proxy(_cached_pac),
        media_type="application/x-ns-proxy-autoconfig",
    )


@app.get("/health")
async def health():
    if _cached_pac is None:
        return Response(status_code=503)
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT)
