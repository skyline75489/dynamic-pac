"""
Whitelist PAC provider for dynamic-pac.

Two-phase design with Redis-backed caching:
1. On startup: try Redis → remote fetch → local fallback file.
   Fresh domain data is written to both Redis (with TTL) and fallback file.
2. Per-request: generate PAC from cached domain list, inject proxy.
   Stale data triggers a background refresh.
"""

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import List

from .fetcher import fetch_domain_list
from .pac_generator import generate_pac_content, PROXY_PLACEHOLDER

logger = logging.getLogger("dynamic-pac.whitelist")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WHITELIST_FALLBACK_PATH = os.getenv(
    "WHITELIST_FALLBACK_PATH", "fallback_domains.json",
).strip()

WHITELIST_CACHE_TTL = int(os.getenv(
    "WHITELIST_CACHE_TTL", "172800",
))

FETCH_PROXY = os.getenv("FETCH_PROXY", "").strip() or None

WHITELIST_REDIS_KEY = "whitelist:domains"

# ---------------------------------------------------------------------------
# Redis (optional, set by app.py at startup)
# ---------------------------------------------------------------------------
_redis = None


def set_redis(client) -> None:
    global _redis
    _redis = client
    if client is not None:
        logger.info("Redis configured for whitelist PAC")


# ---------------------------------------------------------------------------
# Fallback file
# ---------------------------------------------------------------------------
def _save_fallback(domains: List[str]) -> None:
    path = Path(WHITELIST_FALLBACK_PATH)
    try:
        path.write_text(json.dumps(domains, indent=0) + "\n")
        logger.info(
            "Saved fallback domains to %s (%d domains)",
            WHITELIST_FALLBACK_PATH, len(domains),
        )
    except Exception:
        logger.exception("Failed to save fallback domains to %s", WHITELIST_FALLBACK_PATH)


def _load_fallback() -> List[str] | None:
    path = Path(WHITELIST_FALLBACK_PATH)
    if not path.is_file():
        return None
    try:
        domains = json.loads(path.read_text())
        logger.info(
            "Loaded fallback domains from %s (%d domains)",
            WHITELIST_FALLBACK_PATH, len(domains),
        )
        return domains
    except Exception:
        logger.exception("Failed to load fallback domains from %s", WHITELIST_FALLBACK_PATH)
        return None


# ---------------------------------------------------------------------------
# Redis read/write
# ---------------------------------------------------------------------------
async def _read_redis() -> List[str] | None:
    if _redis is None:
        return None
    try:
        data = await _redis.get(WHITELIST_REDIS_KEY)
        if data:
            domains = json.loads(data.decode("utf-8"))
            logger.info("Loaded domains from Redis (%d domains)", len(domains))
            return domains
        logger.info("Redis key %s not found", WHITELIST_REDIS_KEY)
    except Exception:
        logger.exception("Redis read failed")
    return None


async def _write_redis(domains: List[str]) -> None:
    if _redis is None:
        return
    try:
        await _redis.set(
            WHITELIST_REDIS_KEY,
            json.dumps(domains),
            ex=WHITELIST_CACHE_TTL,
        )
        logger.info(
            "Written domains to Redis (TTL=%ds, %d domains)",
            WHITELIST_CACHE_TTL, len(domains),
        )
    except Exception:
        logger.exception("Redis write failed")


# ---------------------------------------------------------------------------
# Remote fetch
# ---------------------------------------------------------------------------
def _fetch_remote() -> List[str] | None:
    try:
        return fetch_domain_list(proxy=FETCH_PROXY)
    except Exception:
        logger.exception("Remote domain fetch failed")
        return None


# ---------------------------------------------------------------------------
# Cached state (in-memory)
# ---------------------------------------------------------------------------
_cached_domains: List[str] | None = None
_cached_at: float = 0.0
_generation_lock = asyncio.Lock()


def _is_stale() -> bool:
    if _cached_domains is None:
        return True
    return (time.monotonic() - _cached_at) >= WHITELIST_CACHE_TTL


# ---------------------------------------------------------------------------
# Source chain: Redis → remote fetch → fallback file
# ---------------------------------------------------------------------------
async def fetch_and_cache_domain_data() -> None:
    """Fetch domain whitelist and cache the raw data.

    Source chain: Redis → remote fetch → local fallback file.
    Success from remote writes to both Redis and fallback file.
    """
    global _cached_domains, _cached_at

    async with _generation_lock:
        loop = asyncio.get_running_loop()

        # 1. Try Redis first
        redis_data = await _read_redis()
        if redis_data is not None:
            _cached_domains = redis_data
            _cached_at = time.monotonic()
            logger.info(
                "Cache seeded from Redis: %d domains", len(redis_data),
            )
            return

        # 2. Try remote fetch
        logger.info("Fetching domain whitelist...")
        fetched = await loop.run_in_executor(None, _fetch_remote)

        if fetched is not None:
            _cached_domains = fetched
            _cached_at = time.monotonic()
            logger.info(
                "Cache seeded from remote: %d domains", len(fetched),
            )
            await _write_redis(fetched)
            await loop.run_in_executor(None, _save_fallback, fetched)
            return

        # 3. Try fallback file
        logger.warning("Remote unreachable, trying fallback file...")
        fallback = await loop.run_in_executor(None, _load_fallback)

        if fallback is not None:
            _cached_domains = fallback
            _cached_at = time.monotonic()
            logger.info(
                "Cache seeded from fallback: %d domains", len(fallback),
            )
            return

        logger.error(
            "All domain data sources exhausted — "
            "whitelist PAC will return 503 until a successful fetch"
        )


async def _do_refresh() -> None:
    """Background refresh: try Redis → remote → fallback."""
    global _cached_domains, _cached_at

    async with _generation_lock:
        logger.info("Whitelist domain refresh started")
        loop = asyncio.get_running_loop()

        # Try Redis first (another replica may have refreshed)
        redis_data = await _read_redis()
        if redis_data is not None:
            _cached_domains = redis_data
            _cached_at = time.monotonic()
            logger.info("Whitelist domains refreshed from Redis")
            return

        # Try remote
        fetched = await loop.run_in_executor(None, _fetch_remote)
        if fetched is not None:
            _cached_domains = fetched
            _cached_at = time.monotonic()
            await _write_redis(fetched)
            await loop.run_in_executor(None, _save_fallback, fetched)
            logger.info("Whitelist domains refreshed from remote")
            return

        # Try fallback
        fallback = await loop.run_in_executor(None, _load_fallback)
        if fallback is not None:
            _cached_domains = fallback
            _cached_at = time.monotonic()
            logger.warning("Remote and Redis failed — using local fallback")


# ---------------------------------------------------------------------------
# PAC generation + proxy injection
# ---------------------------------------------------------------------------
_PLACEHOLDER_RE = re.compile(r"var proxy = '[^']*';")


def _inject_proxy(content: str, proxy: str) -> str:
    return _PLACEHOLDER_RE.sub(
        f"var proxy = '{proxy}';",
        content,
        count=1,
    )


# In-memory cache for the generated PAC template (no args — always the same)
_cached_template: str | None = None
_cached_template_domain_count: int = 0


def _get_template() -> str:
    """Get or build the PAC template from the current domain list.
    Cached in memory until domains change.
    """
    global _cached_template, _cached_template_domain_count

    if _cached_domains is None:
        raise RuntimeError("Domain data not yet fetched")

    if _cached_template is not None and len(_cached_domains) == _cached_template_domain_count:
        return _cached_template

    _cached_template = generate_pac_content(_cached_domains)
    _cached_template_domain_count = len(_cached_domains)
    logger.info(
        "Generated whitelist PAC: %d bytes, %d domains",
        len(_cached_template), _cached_template_domain_count,
    )
    return _cached_template


_refresh_lock = asyncio.Lock()


def get_pac_content(proxy: str) -> str | None:
    """Get a fully rendered whitelist PAC.

    Returns None if domain data hasn't been fetched yet.
    Triggers a background refresh if cached data is stale.
    """
    if _cached_domains is None:
        return None

    if _is_stale():
        _trigger_refresh()

    template = _get_template()
    return _inject_proxy(template, proxy)


def _trigger_refresh() -> None:
    if not _refresh_lock.locked():
        asyncio.create_task(_do_refresh())


def is_ready() -> bool:
    return _cached_domains is not None


def get_domains() -> list[str] | None:
    """Return the cached whitelist domains, or None if not yet fetched."""
    return _cached_domains
