"""
HTTP CONNECT proxy for dynamic-pac.

Routes connections through SOCKS5/HTTP upstream or directly based on
domain matching. Supports two modes:

- gfwlist (default): uses GFWList rules — whitelisted domains → DIRECT,
  blocklisted → PROXY, unknown → DIRECT.
- whitelist: uses dnsmasq-china-list — known Chinese domains → DIRECT,
  everything else → PROXY.

Mode is configured at startup by app.py via configure().
"""

import asyncio
import ipaddress
import logging
import os
import random
import re
import socket
from collections.abc import Callable

from gfwlist.provider import get_rules

logger = logging.getLogger("dynamic-pac.proxy")

# Regexes to parse the PAC_PROXY string
_SOCKS_RE = re.compile(r"SOCKS5?\s+([^:\s]+):(\d+)", re.I)
_HTTP_RE = re.compile(r"PROXY\s+([^:\s]+):(\d+)", re.I)

# Static process settings: these are intentionally read once at startup.
CONNECT_TIMEOUT = float(os.getenv("PROXY_CONNECT_TIMEOUT", "15"))
HEADER_TIMEOUT = float(os.getenv("PROXY_HEADER_TIMEOUT", "10"))
IDLE_TIMEOUT = float(os.getenv("PROXY_IDLE_TIMEOUT", "300"))
RULE_REFRESH_INTERVAL = float(os.getenv("PROXY_RULE_REFRESH_INTERVAL", "300"))
MAX_REQUEST_LINE = int(os.getenv("PROXY_MAX_REQUEST_LINE", "8192"))
MAX_HEADER_BYTES = int(os.getenv("PROXY_MAX_HEADER_BYTES", "32768"))

# ---------------------------------------------------------------------------
# Configurable data sources (set by app.py at startup)
# ---------------------------------------------------------------------------
# Callable returning a set of domains that should go DIRECT, or None if not ready
_get_direct_domains: Callable[[], set[str] | None] | None = None
# Callable returning a set of domains that should go PROXY, or None if not ready
_get_proxy_domains: Callable[[], set[str] | None] | None = None
# Default route for domains that don't match either set
_default_route: str = "DIRECT"

# ---------------------------------------------------------------------------
# Cached routing state
# ---------------------------------------------------------------------------
_direct_set: set[str] = set()
_proxy_set: set[str] = set()
_upstream: dict[str, list[tuple[str, int]]] = {}  # {"socks5": [(h,p),...], "http": ...}
_rules_loaded = False


def configure(
        get_direct_domains: Callable[[], set[str] | None],
        get_proxy_domains: Callable[[], set[str] | None] | None = None,
        default_route: str = "DIRECT",
) -> None:
    """Configure the proxy server's domain data sources.

    Args:
        get_direct_domains: returns domains that should go DIRECT
        get_proxy_domains: optional, returns domains that should go PROXY
        default_route: fallback for unmatched domains ("DIRECT" or "PROXY")
    """
    global _get_direct_domains, _get_proxy_domains, _default_route
    _get_direct_domains = get_direct_domains
    _get_proxy_domains = get_proxy_domains
    _default_route = default_route


# ── GFWList source helpers (used by app.py in gfwlist mode) ────────────────

def _build_domain_sets(rules: list) -> tuple[set[str], set[str]]:
    """Build direct and proxy sets from a parsed GFWList rules array.

    In the PAC: rules[tier][sub_idx] where sub_idx % 2 == 0 → DIRECT,
    sub_idx % 2 == 1 → PROXY.
    """
    direct: set[str] = set()
    proxy: set[str] = set()
    for tier in rules:
        for sub_idx, sublist in enumerate(tier):
            for domain in sublist:
                if sub_idx % 2 == 0:
                    direct.add(domain)
                else:
                    proxy.add(domain)
    return direct, proxy


def get_gfwlist_direct_domains() -> set[str] | None:
    """Return the GFWList whitelist (DIRECT) domains."""
    data = get_rules()
    if data is None:
        return None
    direct, _ = _build_domain_sets(data["rules"])
    return direct


def get_gfwlist_proxy_domains() -> set[str] | None:
    """Return the GFWList blocklist (PROXY) domains."""
    data = get_rules()
    if data is None:
        return None
    _, proxy = _build_domain_sets(data["rules"])
    return proxy


# ── Proxy config parsing ──────────────────────────────────────────────────

def _parse_proxy_config(proxy_str: str) -> dict[str, list[tuple[str, int]]]:
    """Extract upstream proxies from a PAC proxy string.

    Multiple entries of the same type are preserved as a list, in the order
    they appear in `proxy_str`. Selection between them is randomized; the
    caller is expected to try the next one on connect failure.
    """
    result: dict[str, list[tuple[str, int]]] = {}
    for m in _SOCKS_RE.finditer(proxy_str):
        result.setdefault("socks5", []).append((m.group(1), int(m.group(2))))
    for m in _HTTP_RE.finditer(proxy_str):
        result.setdefault("http", []).append((m.group(1), int(m.group(2))))
    return result


def refresh_rules() -> bool:
    """Fetch latest domain data from configured sources and rebuild state.

    Returns True if rules were updated, False if the data source is not
    yet available.
    """
    global _direct_set, _proxy_set, _upstream, _rules_loaded

    if _get_direct_domains is None:
        return False

    direct = _get_direct_domains()
    if direct is None:
        return False

    proxy: set[str] = set()
    if _get_proxy_domains is not None:
        p = _get_proxy_domains()
        if p is not None:
            proxy = p

    # Parse upstream from PAC_PROXY env var (always the live injected value)
    proxy_str = os.getenv("PAC_PROXY", "").strip()
    _upstream = _parse_proxy_config(proxy_str)
    _direct_set = {_normalize_domain(domain) for domain in direct if domain}
    _proxy_set = {_normalize_domain(domain) for domain in proxy if domain}
    _clear_dns_cache()
    _rules_loaded = True

    logger.info(
        "Rules refreshed: %d direct, %d proxy entries, %d upstreams, default=%s",
        len(direct), len(proxy),
        sum(len(v) for v in _upstream.values()), _default_route,
    )
    return True


# ---------------------------------------------------------------------------
# Hardcoded internal/local domains — always DIRECT regardless of mode
# ---------------------------------------------------------------------------
_ALWAYS_DIRECT = frozenset({
    # Kubernetes internal
    "svc", "svc.cluster.local",
    # mDNS / local network
    "local", "localhost",
    # RFC 1918 reverse lookup
    "10.in-addr.arpa", "16.172.in-addr.arpa",
    "17.172.in-addr.arpa", "18.172.in-addr.arpa",
    "19.172.in-addr.arpa", "20.172.in-addr.arpa",
    "21.172.in-addr.arpa", "22.172.in-addr.arpa",
    "23.172.in-addr.arpa", "24.172.in-addr.arpa",
    "25.172.in-addr.arpa", "26.172.in-addr.arpa",
    "27.172.in-addr.arpa", "28.172.in-addr.arpa",
    "29.172.in-addr.arpa", "30.172.in-addr.arpa",
    "31.172.in-addr.arpa", "168.192.in-addr.arpa",
    # HomeAssistant internal
    "homeassistant.local",
})


def _is_always_direct(host: str) -> bool:
    """Check if host should always go DIRECT (internal/local domains)."""
    host_lower = host.lower()
    if host_lower in _ALWAYS_DIRECT:
        return True
    # Check suffix matching for wildcard internal domains
    for suffix in (".svc", ".svc.cluster.local", ".local", ".internal"):
        if host_lower.endswith(suffix):
            return True
    return False


# ── Host matching ──────────────────────────────────────────────────────────

def _is_private_ip(host: str) -> bool:
    """Check if host is a bare IP address in a private range."""
    try:
        addr = ipaddress.ip_address(str(host))
        return addr.is_private
    except ValueError:
        return False


async def get_route(host: str) -> str | None:
    """Determine routing for a host.

    Routing priority:
    1. Internal/local domain suffix → always DIRECT
    2. Private IP address → always DIRECT
    3. `.cn` TLD → DIRECT (matches whitelist PAC behavior)
    4. In the configured direct set → DIRECT
    5. In the configured proxy set → PROXY
    6. Resolves to a private IPv4 address → DIRECT
    7. Default route (configurable: DIRECT or PROXY depending on mode)

    Returns 'DIRECT' or 'PROXY', or None if rules aren't loaded yet.
    """
    if not _rules_loaded:
        return None

    # Internal/local domains always go DIRECT
    if _is_always_direct(host):
        return "DIRECT"

    # Private IP addresses always go DIRECT
    if _is_private_ip(host):
        return "DIRECT"

    # .cn TLD short-circuit: matches the whitelist PAC JS behavior.
    # This catches Chinese domains not in the curated whitelist.
    if host.lower().endswith(".cn"):
        return "DIRECT"

    if _match_domain(host, _direct_set):
        return "DIRECT"
    if _proxy_set and _match_domain(host, _proxy_set):
        return "PROXY"

    # For hostnames not in any list, try DNS resolution once per refresh
    # If it resolves to a private IP, treat as DIRECT (handles k8s internal)
    if await _resolves_to_private(host):
        return "DIRECT"

    return _default_route


_dns_cache: dict[str, bool | None] = {}


async def _resolves_to_private(host: str) -> bool | None:
    """Check if hostname resolves to a private IP address.

    Returns True/False, or None if resolution failed. The caller applies the
    mode-specific default route for False and None. Results, including failed
    resolutions, are cached until the next rules refresh.
    """
    # Strip port if present (shouldn't happen but be safe)
    hostname = host.split(":")[0].lower()

    # Skip bare IPs (already handled above)
    if _is_private_ip(hostname):
        return True

    if hostname in _dns_cache:
        return _dns_cache[hostname]

    try:
        loop = asyncio.get_running_loop()
        addrs = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in addrs:
            ip = sockaddr[0]
            # Only check IPv4 for private range; Python's ipaddress marks
            # some non-private IPv6 ranges (e.g. 2001::/23 for TEREDO) as
            # private, which would falsely classify hosts like google.com
            # as internal.
            if family == socket.AF_INET and _is_private_ip(ip):
                _dns_cache[hostname] = True
                return True
        _dns_cache[hostname] = False
        return False
    except (OSError, socket.gaierror):
        # Resolution failure may mean non-existent host on this network
        # Let the default route handle it
        _dns_cache[hostname] = None
        return None


def _clear_dns_cache() -> None:
    _dns_cache.clear()


def _normalize_domain(domain: str) -> str:
    """Normalize a DNS name for exact and suffix matching."""
    return domain.strip().lower().rstrip(".")


def _match_domain(host: str, domain_set: set[str]) -> bool:
    """Check if host matches any domain in domain_set (exact or subdomain).

    Domain matching is case-insensitive — HTTP hostnames are case-insensitive
    per RFC 3986, but clients may send CONNECT targets with mixed case.
    """
    labels = _normalize_domain(host).split(".")
    for index in range(len(labels)):
        if ".".join(labels[index:]) in domain_set:
            return True
    return False


# ── Upstream connections ───────────────────────────────────────────────────

async def _socks5_connect(
    host: str, port: int, proxy_host: str, proxy_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to host:port through a SOCKS5 proxy.

    Raises ValueError on protocol-level rejection (unsupported version,
    auth required, refused/banned address type) or asyncio.IncompleteReadError
    if the upstream closes mid-handshake. On any failure the TCP writer
    is closed before raising, so the caller does not need to clean up.
    """
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    try:
        # SOCKS5 greeting: no auth
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await reader.readexactly(2)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise ValueError(f"SOCKS5 handshake failed: {resp.hex()}")

        # CONNECT request with the appropriate address type.
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            host_bytes = host.encode("idna")
            if len(host_bytes) > 255:
                raise ValueError("SOCKS5 destination hostname is too long")
            encoded_host = b"\x03" + bytes([len(host_bytes)]) + host_bytes
        else:
            encoded_host = (b"\x01" if address.version == 4 else b"\x04") + address.packed
        req = b"\x05\x01\x00" + encoded_host + port.to_bytes(2, "big")
        writer.write(req)
        await writer.drain()

        # Read response header
        resp = await reader.readexactly(4)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise ValueError(
                f"SOCKS5 connect failed for {host}:{port}: {resp.hex()}"
            )

        # Skip remaining address info
        atype = resp[3]
        if atype == 0x01:
            await reader.readexactly(6)       # 4 IPv4 + 2 port
        elif atype == 0x03:
            dlen = (await reader.readexactly(1))[0]
            await reader.readexactly(dlen + 2)  # domain + port
        elif atype == 0x04:
            await reader.readexactly(18)      # 16 IPv6 + 2 port
        else:
            raise ValueError(f"SOCKS5 returned unknown address type: {atype}")
    except BaseException:
        # Close the writer on any handshake failure (including
        # IncompleteReadError if the upstream hangs up mid-handshake, or
        # asyncio.CancelledError if the caller times us out). The closed
        # socket lets the OS release the file descriptor promptly.
        try:
            writer.close()
        except Exception:
            pass
        raise
    return reader, writer


async def _http_proxy_connect(
    host: str, port: int, proxy_host: str, proxy_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to host:port through an HTTP CONNECT proxy.

    Raises ValueError on non-2xx proxy responses, or
    asyncio.IncompleteReadError / OSError if the upstream closes or stalls
    mid-handshake. On any failure the TCP writer is closed before raising,
    so the caller does not need to clean up.
    """
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    try:
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()

        resp = await reader.readline()
        parts = resp.decode("iso-8859-1", errors="replace").split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) != 200:
            raise ValueError(
                f"HTTP proxy connect failed for {host}:{port}: "
                f"{resp.decode().strip()}"
            )

        # Drain remaining response headers
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
    except BaseException:
        # Close the writer on any handshake failure (including
        # IncompleteReadError if the upstream closes mid-response, or
        # asyncio.CancelledError if the caller times us out). The closed
        # socket lets the OS release the file descriptor promptly.
        try:
            writer.close()
        except Exception:
            pass
        raise
    return reader, writer


async def _direct_connect(
    host: str, port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect directly over IPv4; this deployment has no IPv6 route."""
    return await asyncio.open_connection(host, port, family=socket.AF_INET)


async def _connect_with_failover(
    host: str, port: int, proxy_type: str,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
    """Connect via one of the configured upstreams of the given type.

    Tries upstreams in a fresh randomized order on every call (uniform
    random choice, not sticky — favors load-spread over connection reuse
    for short-lived CONNECTs). On connect failure (OSError or per-upstream
    timeout) advances to the next candidate.

    Budgeting: the outer CONNECT_TIMEOUT bounds the *total* time across all
    attempts. Each attempt is given `remaining / candidates_left` so a
    stalled/blackholed first upstream cannot consume the whole budget and
    starve the healthy backups — without this, one silently-dropped SYN
    makes load-balancing unreliable whenever a backend is blackholed
    rather than failing fast.

    Returns (reader, writer, "<type>://<host>:<port>") describing the
    upstream that succeeded.
    """
    candidates = list(_upstream.get(proxy_type, []))
    if not candidates:
        raise ValueError(f"no upstream configured for type={proxy_type!r}")
    random.shuffle(candidates)

    loop = asyncio.get_running_loop()
    deadline = loop.time() + CONNECT_TIMEOUT
    last_err: Exception | None = None
    tried: list[str] = []

    remaining_candidates = len(candidates)
    for ph, pp in candidates:
        remaining_candidates -= 1
        now = loop.time()
        if now >= deadline:
            break
        # Per-attempt slice: share the remaining budget across this attempt
        # plus any not-yet-tried candidates, so a stalled upstream cannot
        # consume the whole deadline before backups are tried.
        slice_budget = (deadline - now) / (remaining_candidates + 1)
        tried.append(f"{ph}:{pp}")
        try:
            if proxy_type == "socks5":
                coro = _socks5_connect(host, port, ph, pp)
            else:
                coro = _http_proxy_connect(host, port, ph, pp)
            reader, writer = await asyncio.wait_for(coro, timeout=slice_budget)
            return reader, writer, f"{proxy_type}://{ph}:{pp}"
        except (OSError, ConnectionError, ValueError,
                asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            last_err = e
            logger.debug(
                "Upstream %s://%s:%s failed for %s:%d: %s",
                proxy_type, ph, pp, host, port, e,
            )
            continue

    # All candidates exhausted within the deadline.
    raise ConnectionError(
        f"all upstreams failed for {host}:{port} "
        f"(tried {tried}, last error: {last_err})"
    )


# ── Data piping ────────────────────────────────────────────────────────────

async def _pipe(reader: asyncio.StreamReader,
                writer: asyncio.StreamWriter) -> None:
    """Bidirectional data copy until EOF or error."""
    try:
        while True:
            if IDLE_TIMEOUT > 0:
                data = await asyncio.wait_for(
                    reader.read(65536), timeout=IDLE_TIMEOUT,
                )
            else:
                data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.TimeoutError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── CONNECT handler ────────────────────────────────────────────────────────

async def handle_connect(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
) -> None:
    """Handle a single CONNECT request."""
    try:
        # Read the CONNECT request line
        data = await asyncio.wait_for(reader.readline(), timeout=HEADER_TIMEOUT)
        if not data:
            writer.close()
            return
        if len(data) > MAX_REQUEST_LINE:
            writer.write(b"HTTP/1.1 414 URI Too Long\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        line = data.decode("iso-8859-1").strip()
        parts = line.split()

        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # Parse host:port from the request target
        target = parts[1]
        if target.startswith("[") and "]:" in target:
            host, port_str = target[1:].rsplit("]:", 1)
        elif target.count(":") == 1:
            host, port_str = target.rsplit(":", 1)
        elif ":" in target:
            host, port_str = target.strip("[]"), "443"
        else:
            host, port_str = target, "443"

        try:
            port = int(port_str)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        if not host:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        # Drain remaining request headers with size and time limits.
        header_bytes = 0
        while True:
            hdr = await asyncio.wait_for(reader.readline(), timeout=HEADER_TIMEOUT)
            header_bytes += len(hdr)
            if header_bytes > MAX_HEADER_BYTES:
                writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return
            if hdr in (b"\r\n", b"\n", b""):
                break

        route = await get_route(host)
        if route is None:
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # Connect to the selected destination with an overall deadline.
        # For PROXY routes with multiple upstreams of the chosen type, try
        # in randomized order, advancing on connect failure.
        try:
            if route == "DIRECT":
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    _direct_connect(host, port), timeout=CONNECT_TIMEOUT,
                )
                chosen_route = "DIRECT"
            elif "socks5" in _upstream:
                upstream_reader, upstream_writer, chosen_route = \
                    await _connect_with_failover(host, port, "socks5")
            elif "http" in _upstream:
                upstream_reader, upstream_writer, chosen_route = \
                    await _connect_with_failover(host, port, "http")
            else:
                raise ValueError("route requires a proxy but no upstream is configured")
        except (OSError, ConnectionError, ValueError, asyncio.TimeoutError) as e:
            logger.warning("Connect failed: %s -> %s: %s", host, route, e)
            writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            return

        # Signal success to the client
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        logger.info("Tunnel established: %s:%d -> %s", host, port, chosen_route)

        # Bidirectional pipe
        task_a = asyncio.create_task(_pipe(reader, upstream_writer))
        task_b = asyncio.create_task(_pipe(upstream_reader, writer))
        _, pending = await asyncio.wait(
            [task_a, task_b], return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(task_a, task_b, return_exceptions=True)

        logger.info("Tunnel closed: %s:%d", host, port)

    except (ConnectionError, OSError, asyncio.TimeoutError) as e:
        logger.debug("Connection error: %s", e)
    except Exception:
        logger.exception("Unexpected error in CONNECT handler")
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── Server lifecycle ───────────────────────────────────────────────────────

async def start(host: str = "0.0.0.0",
                port: int = 8888,
                ready_event: asyncio.Event | None = None) -> None:
    """Start the CONNECT proxy server.

    Blocks until the server is stopped (call from a task).
    """
    # Initial rules load — retry until available
    while not _rules_loaded:
        if refresh_rules():
            break
        logger.info("Waiting for PAC rules to be seeded...")
        await asyncio.sleep(2)

    server = await asyncio.start_server(handle_connect, host, port)

    async def refresh_periodically() -> None:
        while True:
            await asyncio.sleep(RULE_REFRESH_INTERVAL)
            try:
                refresh_rules()
            except Exception:
                logger.exception("Failed to refresh CONNECT proxy rules")

    refresh_task = None
    if RULE_REFRESH_INTERVAL > 0:
        refresh_task = asyncio.create_task(refresh_periodically())

    if ready_event is not None:
        ready_event.set()

    logger.info("CONNECT proxy listening on %s:%d (%d direct, %d proxy, default=%s)",
                host, port, len(_direct_set), len(_proxy_set), _default_route)

    try:
        async with server:
            await server.serve_forever()
    finally:
        if refresh_task is not None:
            refresh_task.cancel()
            await asyncio.gather(refresh_task, return_exceptions=True)
