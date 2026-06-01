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
import logging
import os
import re
from collections.abc import Callable

from gfwlist.provider import get_rules

logger = logging.getLogger("dynamic-pac.proxy")

# Regexes to parse the PAC_PROXY string
_SOCKS_RE = re.compile(r"SOCKS5?\s+([^:\s]+):(\d+)", re.I)
_HTTP_RE = re.compile(r"PROXY\s+([^:\s]+):(\d+)", re.I)

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
_upstream: dict[str, tuple[str, int]] = {}  # {"socks5": (host, port), "http": ...}
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

def _parse_proxy_config(proxy_str: str) -> dict[str, tuple[str, int]]:
    """Extract upstream proxies from a PAC proxy string."""
    result: dict[str, tuple[str, int]] = {}
    socks = _SOCKS_RE.search(proxy_str)
    if socks:
        result["socks5"] = (socks.group(1), int(socks.group(2)))
    http = _HTTP_RE.search(proxy_str)
    if http:
        result["http"] = (http.group(1), int(http.group(2)))
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
    _direct_set = direct
    _proxy_set = proxy
    _clear_dns_cache()
    _rules_loaded = True

    logger.info(
        "Rules refreshed: %d direct, %d proxy entries, %d upstreams, default=%s",
        len(direct), len(proxy), len(_upstream), _default_route,
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
    import ipaddress
    try:
        addr = ipaddress.ip_address(str(host))
        return addr.is_private
    except ValueError:
        return False


def get_route(host: str) -> str | None:
    """Determine routing for a host.

    Routing priority:
    1. Internal/local domain suffix → always DIRECT
    2. Private IP address → always DIRECT
    3. In the configured direct set → DIRECT
    4. In the configured proxy set → PROXY
    5. Default route (configurable: DIRECT or PROXY depending on mode)

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

    if _match_domain(host, _direct_set):
        return "DIRECT"
    if _proxy_set and _match_domain(host, _proxy_set):
        return "PROXY"

    # For hostnames not in any list, try DNS resolution once per refresh
    # If it resolves to a private IP, treat as DIRECT (handles k8s internal)
    if _resolves_to_private(host):
        return "DIRECT"

    return _default_route


_dns_cache: dict[str, bool | None] = {}


def _resolves_to_private(host: str) -> bool | None:
    """Check if hostname resolves to a private IP address.

    Returns True/False, or None if resolution failed (treat as proxy).
    Results are cached per refresh cycle.
    """
    # Strip port if present (shouldn't happen but be safe)
    hostname = host.split(":")[0].lower()

    # Skip bare IPs (already handled above)
    if _is_private_ip(hostname):
        return True

    cached = _dns_cache.get(hostname)
    if cached is not None:
        return cached

    try:
        import socket
        addrs = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addrs:
            ip = sockaddr[0]
            if _is_private_ip(ip):
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

def _match_domain(host: str, domain_set: set[str]) -> bool:
    """Check if host matches any domain in domain_set (exact or subdomain)."""
    if host in domain_set:
        return True
    for domain in domain_set:
        if host.endswith("." + domain):
            return True
    return False


# ── Upstream connections ───────────────────────────────────────────────────

async def _socks5_connect(
    host: str, port: int, proxy_host: str, proxy_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to host:port through a SOCKS5 proxy."""
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

    # SOCKS5 greeting: no auth
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    if resp[0] != 0x05 or resp[1] != 0x00:
        writer.close()
        raise ValueError(f"SOCKS5 handshake failed: {resp.hex()}")

    # CONNECT request (domain name type)
    host_bytes = host.encode("idna")
    req = (
        b"\x05\x01\x00\x03"
        + bytes([len(host_bytes)])
        + host_bytes
        + port.to_bytes(2, "big")
    )
    writer.write(req)
    await writer.drain()

    # Read response header
    resp = await reader.readexactly(4)
    if resp[0] != 0x05 or resp[1] != 0x00:
        writer.close()
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

    return reader, writer


async def _http_proxy_connect(
    host: str, port: int, proxy_host: str, proxy_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to host:port through an HTTP CONNECT proxy."""
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    writer.write(req.encode())
    await writer.drain()

    resp = await reader.readline()
    parts = resp.decode().split(" ", 2)
    if int(parts[1]) != 200:
        writer.close()
        raise ValueError(
            f"HTTP proxy connect failed for {host}:{port}: "
            f"{resp.decode().strip()}"
        )

    # Drain remaining response headers
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break

    return reader, writer


async def _direct_connect(
    host: str, port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect directly to host:port."""
    return await asyncio.open_connection(host, port)


# ── Data piping ────────────────────────────────────────────────────────────

async def _pipe(reader: asyncio.StreamReader,
                writer: asyncio.StreamWriter) -> None:
    """Bidirectional data copy until EOF or error."""
    try:
        while True:
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
        data = await reader.readline()
        if not data:
            writer.close()
            return

        line = data.decode().strip()
        parts = line.split(" ")

        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # Parse host:port from the request target
        target = parts[1]
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                writer.close()
                return
        else:
            host = target
            port = 443  # default for CONNECT

        # Drain any remaining request headers
        while True:
            hdr = await reader.readline()
            if hdr in (b"\r\n", b"\n", b""):
                break

        route = get_route(host)
        if route is None:
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # Connect to upstream
        try:
            if route == "DIRECT":
                upstream_reader, upstream_writer = await _direct_connect(
                    host, port,
                )
            else:
                # Prefer SOCKS5, fall back to HTTP CONNECT
                if "socks5" in _upstream:
                    ph, pp = _upstream["socks5"]
                    upstream_reader, upstream_writer = await _socks5_connect(
                        host, port, ph, pp,
                    )
                elif "http" in _upstream:
                    ph, pp = _upstream["http"]
                    upstream_reader, upstream_writer = \
                        await _http_proxy_connect(host, port, ph, pp)
                else:
                    upstream_reader, upstream_writer = await _direct_connect(
                        host, port,
                    )
        except (OSError, ConnectionError, ValueError) as e:
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

        logger.info("Tunnel established: %s:%d -> %s", host, port, route)

        # Bidirectional pipe
        task_a = asyncio.create_task(_pipe(reader, upstream_writer))
        task_b = asyncio.create_task(_pipe(upstream_reader, writer))
        done, _ = await asyncio.wait(
            [task_a, task_b], return_when=asyncio.FIRST_COMPLETED,
        )
        # Cancel the other task
        for t in done:
            other = task_b if t is task_a else task_a
            other.cancel()

        logger.info("Tunnel closed: %s:%d", host, port)

    except (ConnectionError, OSError) as e:
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

    if ready_event is not None:
        ready_event.set()

    logger.info("CONNECT proxy listening on %s:%d (%d direct, %d proxy, default=%s)",
                host, port, len(_direct_set), len(_proxy_set), _default_route)

    async with server:
        await server.serve_forever()
