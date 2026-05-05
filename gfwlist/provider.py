"""
GFWList / remote PAC provider for dynamic-pac.

Two-phase design with Redis-backed caching:
1. On startup / seed: try Redis -> remote URL -> local fallback file.
   Raw PAC content (without proxy) is cached.
2. Per-request: inject PAC_PROXY via regex replacement.
   Stale data triggers a background refresh.
"""

import asyncio
import logging
import os
import re
import time
from pathlib import Path

import httpx

logger = logging.getLogger("dynamic-pac.gfwlist")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REMOTE_PAC_URL = os.getenv("REMOTE_PAC_URL", "").strip()
FETCH_PROXY = os.getenv("FETCH_PROXY", "").strip() or None
GFWLIST_CACHE_TTL = int(os.getenv("GFWLIST_CACHE_TTL", "86400"))
FALLBACK_PAC_PATH = os.getenv("FALLBACK_PAC_PATH", "fallback.pac").strip()

if not REMOTE_PAC_URL:
    raise RuntimeError("REMOTE_PAC_URL environment variable is required")

GFWLIST_REDIS_KEY = "gfwlist:content"

# ---------------------------------------------------------------------------
# Redis (optional, set by app.py at startup)
# ---------------------------------------------------------------------------
_redis = None


def set_redis(client) -> None:
    global _redis
    _redis = client
    if client is not None:
        logger.info("Redis configured for gfwlist PAC")


# ---------------------------------------------------------------------------
# Proxy injection
# ---------------------------------------------------------------------------
_PROXY_RE = re.compile(r"var\s+proxy\s*=\s*'[^']*'\s*;")


def _inject_proxy(content: str, proxy: str) -> str:
    new = _PROXY_RE.sub(lambda _: f"var proxy = '{proxy}';", content, count=1)
    if new == content:
        logger.warning("proxy var not found in PAC — prepending")
        new = f"var proxy = '{proxy}';\n{content}"
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
        data = await _redis.get(GFWLIST_REDIS_KEY)
        if data:
            logger.info("Loaded PAC from Redis (%d bytes)", len(data))
            return data.decode("utf-8")
        logger.info("Redis key %s not found", GFWLIST_REDIS_KEY)
    except Exception:
        logger.exception("Redis read failed")
    return None


async def _write_redis(content: str) -> None:
    if _redis is None:
        return
    try:
        await _redis.set(GFWLIST_REDIS_KEY, content, ex=GFWLIST_CACHE_TTL)
        logger.info("Written to Redis (TTL=%ds)", GFWLIST_CACHE_TTL)
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
# In-memory cache
# ---------------------------------------------------------------------------
_cached_pac: str | None = None
_cached_at: float = 0.0
_seed_lock = asyncio.Lock()
_refresh_lock = asyncio.Lock()


def _is_stale() -> bool:
    if _cached_pac is None:
        return True
    return (time.monotonic() - _cached_at) >= GFWLIST_CACHE_TTL


# ---------------------------------------------------------------------------
# Source chain: Redis -> remote -> fallback
# ---------------------------------------------------------------------------
async def seed_cache() -> None:
    """Seed the cache at startup. Must be awaited before serving traffic."""
    global _cached_pac, _cached_at

    async with _seed_lock:
        # Try Redis first (another replica may have cached it)
        content = await _read_redis()
        if content is not None:
            _cached_pac, _cached_at = content, time.monotonic()
            logger.info("Cache seeded from Redis")
            return

        content = await _fetch_remote()
        if content is not None:
            _cached_pac, _cached_at = content, time.monotonic()
            await _write_redis(content)
            logger.info("Cache seeded from remote")
            return

        content = _load_fallback()
        if content is not None:
            _cached_pac, _cached_at = content, time.monotonic()
            logger.info("Cache seeded from fallback")
            return

        logger.error("All sources exhausted — starting empty")


def _trigger_refresh() -> None:
    if not _refresh_lock.locked():
        asyncio.create_task(_do_refresh())


async def _do_refresh() -> None:
    global _cached_pac, _cached_at
    async with _refresh_lock:
        logger.info("Cache refresh started")

        # Try Redis first (another replica may have refreshed)
        content = await _read_redis()
        if content is not None:
            _cached_pac, _cached_at = content, time.monotonic()
            logger.info("Cache refreshed from Redis")
            return

        content = await _fetch_remote()
        if content is not None:
            _cached_pac, _cached_at = content, time.monotonic()
            await _write_redis(content)
            logger.info("Cache refreshed from remote")
            return

        content = _load_fallback()
        if content is not None:
            _cached_pac, _cached_at = content, time.monotonic()
            logger.warning("Remote and Redis failed — using local fallback")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_pac_content(proxy: str) -> str | None:
    """Return the remote PAC with proxy injected.

    Returns None if cache hasn't been seeded yet.
    Triggers a background refresh if stale.
    """
    if _cached_pac is None:
        return None

    if _is_stale():
        _trigger_refresh()

    return _inject_proxy(_cached_pac, proxy)


def is_ready() -> bool:
    return _cached_pac is not None
