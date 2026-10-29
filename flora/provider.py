"""
Flora PAC provider for dynamic-pac.

Two-phase design with Redis-backed caching:
1. On startup: try Redis → APNIC → local fallback file.
   Fresh APNIC data is written to both Redis (with TTL) and fallback file.
2. Per-request: fragment + hash with the requested hash_base/mask_step,
   then inject proxy. Stale data triggers a background refresh.
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
from functools import lru_cache
from pathlib import Path

from .ip_data import fetch_ip_data, merge_all
from .network_ops import calculate_prefix_range, fregment_nets, hash_nets
from .pac_generator import PROXY_PLACEHOLDER, generate_pac_content_from_data

logger = logging.getLogger("dynamic-pac.flora")

_PLACEHOLDER_RE = re.compile(
    re.escape(f"return '{PROXY_PLACEHOLDER}' ;"),
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
FLORA_FALLBACK_PATH = os.getenv(
    "FLORA_FALLBACK_PATH",
    "fallback_ip_cn.json",
).strip()

FLORA_CACHE_TTL = int(
    os.getenv(
        "FLORA_CACHE_TTL",
        "604800",  # 7 days
    )
)

FLORA_REDIS_KEY = "flora:ip_data"

# ---------------------------------------------------------------------------
# Redis (optional, set by app.py at startup)
# ---------------------------------------------------------------------------
_redis = None


def set_redis(client) -> None:
    """Set the Redis client for persistent caching across replicas."""
    global _redis
    _redis = client
    if client is not None:
        logger.info("Redis configured for Flora PAC")


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------
def _serialize_nets(nets: list[ipaddress.IPv4Network]) -> list[str]:
    return sorted(str(n) for n in nets)


def _deserialize_nets(cidrs: list[str]) -> list[ipaddress.IPv4Network]:
    return [ipaddress.IPv4Network(c) for c in cidrs]


# ---------------------------------------------------------------------------
# Fallback file
# ---------------------------------------------------------------------------
def _save_fallback(results: list[ipaddress.IPv4Network]) -> None:
    path = Path(FLORA_FALLBACK_PATH)
    try:
        cidrs = _serialize_nets(results)
        path.write_text(json.dumps(cidrs, indent=0) + "\n")
        logger.info(
            "Saved fallback IP data to %s (%d networks)",
            FLORA_FALLBACK_PATH,
            len(cidrs),
        )
    except Exception:
        logger.exception("Failed to save fallback IP data to %s", FLORA_FALLBACK_PATH)


def _load_fallback() -> tuple[list[ipaddress.IPv4Network], int, int] | None:
    path = Path(FLORA_FALLBACK_PATH)
    if not path.is_file():
        return None
    try:
        cidrs = json.loads(path.read_text())
        results = _deserialize_nets(cidrs)
        min_p, max_p = calculate_prefix_range(results)
        logger.info(
            "Loaded fallback IP data from %s (%d networks)",
            FLORA_FALLBACK_PATH,
            len(results),
        )
        return results, min_p, max_p
    except Exception:
        logger.exception("Failed to load fallback IP data from %s", FLORA_FALLBACK_PATH)
        return None


# ---------------------------------------------------------------------------
# Redis read/write
# ---------------------------------------------------------------------------
async def _read_redis() -> tuple[list[ipaddress.IPv4Network], int, int] | None:
    if _redis is None:
        return None
    try:
        data = await _redis.get(FLORA_REDIS_KEY)
        if data:
            cidrs = json.loads(data.decode("utf-8"))
            results = _deserialize_nets(cidrs)
            min_p, max_p = calculate_prefix_range(results)
            logger.info(
                "Loaded IP data from Redis (%d networks)",
                len(results),
            )
            return results, min_p, max_p
        logger.info("Redis key %s not found", FLORA_REDIS_KEY)
    except Exception:
        logger.exception("Redis read failed")
    return None


async def _write_redis(results: list[ipaddress.IPv4Network]) -> None:
    if _redis is None:
        return
    try:
        cidrs = _serialize_nets(results)
        await _redis.set(FLORA_REDIS_KEY, json.dumps(cidrs), ex=FLORA_CACHE_TTL)
        logger.info(
            "Written IP data to Redis (TTL=%ds, %d networks)",
            FLORA_CACHE_TTL,
            len(cidrs),
        )
    except Exception:
        logger.exception("Redis write failed")


# ---------------------------------------------------------------------------
# APNIC fetch
# ---------------------------------------------------------------------------
def _fetch_apnic() -> tuple[list[ipaddress.IPv4Network], int, int] | None:
    try:
        results = merge_all(fetch_ip_data())
        min_p, max_p = calculate_prefix_range(results)
        return results, min_p, max_p
    except Exception:
        logger.exception("APNIC fetch failed")
        return None


# ---------------------------------------------------------------------------
# Cached state (in-memory)
# ---------------------------------------------------------------------------
_cached_results: list[ipaddress.IPv4Network] | None = None
_min_prefixlen: int = 32
_max_prefixlen: int = 0
_cached_at: float = 0.0
_generation_lock = asyncio.Lock()


def _is_stale() -> bool:
    if _cached_results is None:
        return True
    return (time.monotonic() - _cached_at) >= FLORA_CACHE_TTL


# ---------------------------------------------------------------------------
# Source chain: Redis → APNIC → fallback file
# ---------------------------------------------------------------------------
async def fetch_and_cache_ip_data() -> None:
    """Fetch China IP ranges and cache the raw data.

    Source chain: Redis → APNIC → local fallback file.
    APNIC success writes to both Redis and fallback file.
    """
    global _cached_results, _min_prefixlen, _max_prefixlen, _cached_at

    async with _generation_lock:
        loop = asyncio.get_running_loop()

        # 1. Try Redis first
        redis_data = await _read_redis()
        if redis_data is not None:
            results, min_p, max_p = redis_data
            _cached_results = results
            _min_prefixlen = min_p
            _max_prefixlen = max_p
            _cached_at = time.monotonic()
            logger.info(
                "Cache seeded from Redis: %d IP ranges (prefix: [%d, %d])",
                len(results),
                min_p,
                max_p,
            )
            return

        # 2. Try APNIC
        logger.info("Fetching China IP ranges from APNIC...")
        fetched = await loop.run_in_executor(None, _fetch_apnic)

        if fetched is not None:
            results, min_p, max_p = fetched
            _cached_results = results
            _min_prefixlen = min_p
            _max_prefixlen = max_p
            _cached_at = time.monotonic()
            logger.info(
                "Cache seeded from APNIC: %d IP ranges (prefix: [%d, %d])",
                len(results),
                min_p,
                max_p,
            )
            # Persist for future boots
            await _write_redis(results)
            await loop.run_in_executor(None, _save_fallback, results)
            return

        # 3. Try fallback file
        logger.warning("APNIC unreachable, trying fallback file...")
        fallback = await loop.run_in_executor(None, _load_fallback)

        if fallback is not None:
            results, min_p, max_p = fallback
            _cached_results = results
            _min_prefixlen = min_p
            _max_prefixlen = max_p
            _cached_at = time.monotonic()
            logger.info(
                "Cache seeded from fallback: %d IP ranges (prefix: [%d, %d])",
                len(results),
                min_p,
                max_p,
            )
            return

        logger.error(
            "All IP data sources exhausted — Flora PAC will return 503 until a successful fetch"
        )


async def _do_refresh() -> None:
    """Background refresh: try Redis → APNIC → fallback."""
    global _cached_results, _min_prefixlen, _max_prefixlen, _cached_at

    async with _generation_lock:
        logger.info("Flora IP data refresh started")
        loop = asyncio.get_running_loop()

        # Try Redis first (another replica may have refreshed)
        redis_data = await _read_redis()
        if redis_data is not None:
            results, min_p, max_p = redis_data
            _cached_results = results
            _min_prefixlen = min_p
            _max_prefixlen = max_p
            _cached_at = time.monotonic()
            logger.info("Flora IP data refreshed from Redis")
            return

        # Try APNIC
        fetched = await loop.run_in_executor(None, _fetch_apnic)
        if fetched is not None:
            results, min_p, max_p = fetched
            _cached_results = results
            _min_prefixlen = min_p
            _max_prefixlen = max_p
            _cached_at = time.monotonic()
            await _write_redis(results)
            await loop.run_in_executor(None, _save_fallback, results)
            logger.info("Flora IP data refreshed from APNIC")
            return

        # Try fallback
        fallback = await loop.run_in_executor(None, _load_fallback)
        if fallback is not None:
            results, min_p, max_p = fallback
            _cached_results = results
            _min_prefixlen = min_p
            _max_prefixlen = max_p
            _cached_at = time.monotonic()
            logger.warning("Remote and Redis failed — using local fallback")


# ---------------------------------------------------------------------------
# PAC generation
# ---------------------------------------------------------------------------
def _build_template(
    hash_base: int,
    mask_step: int,
) -> tuple[str, int]:
    if _cached_results is None:
        raise RuntimeError("IP data not yet fetched")

    fragmented = fregment_nets(_cached_results, mask_step)
    hashed = hash_nets(fragmented, hash_base)

    content = generate_pac_content_from_data(
        hashed,
        hash_base,
        mask_step,
        _min_prefixlen,
        _max_prefixlen,
    )
    return content, len(_cached_results)


@lru_cache(maxsize=32)
def _uncached_generate(hash_base: int, mask_step: int) -> tuple[str, int]:
    content, rules_count = _build_template(hash_base, mask_step)
    logger.info(
        "Generated Flora PAC: %d bytes, %d rules, hash_base=%d, mask_step=%d",
        len(content),
        rules_count,
        hash_base,
        mask_step,
    )
    return content, rules_count


_refresh_lock = asyncio.Lock()


def get_pac_content(hash_base: int, mask_step: int, proxy: str) -> str | None:
    """Get a fully rendered Flora PAC for the given parameters.

    Returns None if IP data hasn't been fetched yet.
    Triggers a background refresh if cached data is stale.
    """
    if _cached_results is None:
        return None

    if _is_stale():
        _trigger_refresh()

    template, _ = _uncached_generate(hash_base, mask_step)
    return _inject_proxy(template, proxy)


def _inject_proxy(content: str, proxy: str) -> str:
    new_content = _PLACEHOLDER_RE.sub(
        lambda _: f"return '{proxy}' ;",
        content,
        count=1,
    )
    if new_content == content:
        logger.warning("Flora PAC placeholder not found — prepending proxy line")
        new_content = content.rstrip("\n") + f"\n\nvar proxy = '{proxy}';\n"
    return new_content


def _trigger_refresh() -> None:
    if not _refresh_lock.locked():
        asyncio.create_task(_do_refresh())


def is_ready() -> bool:
    return _cached_results is not None
