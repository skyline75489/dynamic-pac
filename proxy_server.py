"""
HTTP CONNECT + forward proxy for dynamic-pac.

Routes requests through SOCKS5/HTTP upstream or directly based on
domain matching. Supports two modes:

- gfwlist (default): uses GFWList rules — whitelisted domains → DIRECT,
  blocklisted → PROXY, unknown → DIRECT.
- whitelist: uses dnsmasq-china-list — known Chinese domains → DIRECT,
  everything else → PROXY.

Mode is configured at startup by app.py via configure().

Protocols handled:
- CONNECT host:port  → tunnel bytes (used for HTTPS and arbitrary TCP)
- GET/POST/...      → forward HTTP, with WebSocket upgrade pass-through

Ordinary HTTP connections serve one request and explicitly close afterward.
Responses stream without a size cap; uploads are buffered up to 64 MiB.
Use CONNECT for HTTPS. Direct connections use IPv4, as in the original proxy.
"""

import asyncio
import ipaddress
import logging
import os
import random
import re
import socket
from collections.abc import AsyncIterator, Callable
from urllib.parse import SplitResult, urlsplit

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
RESPONSE_HEADER_TIMEOUT = float(os.getenv("PROXY_RESPONSE_HEADER_TIMEOUT", "30"))

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
    they appear in `proxy_str`. Each request tries a randomized order with
    budgeted failover across candidates of the preferred proxy type.
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


# ── Upstream selection ─────────────────────────────────────────────────────

def _select_proxy_url() -> tuple[str, list[tuple[str, int]]] | None:
    """Pick a scheme and return (scheme, candidates).

    SOCKS5 upstreams are preferred over HTTP upstreams when both are
    configured. Returns the list of candidates (not a single one) so
    `_connect_with_failover` can shuffle and try multiple upstreams.

    Returns None when no upstreams are configured (DIRECT).
    """
    if _upstream.get("socks5"):
        return "socks5", list(_upstream["socks5"])
    if _upstream.get("http"):
        return "http", list(_upstream["http"])
    return None


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


# ── HTTP header reading helpers ────────────────────────────────────────────

async def _read_request_headers(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
) -> tuple[bytes, dict[str, str]] | None:
    """Read the request line + headers, return (raw_request_line, headers).

    Enforces MAX_REQUEST_LINE / MAX_HEADER_BYTES / HEADER_TIMEOUT. Returns
    None if the client disconnects or sends an oversized request.
    """
    try:
        data = await asyncio.wait_for(reader.readline(), timeout=HEADER_TIMEOUT)
    except asyncio.TimeoutError:
        return None
    if not data:
        return None
    if len(data) > MAX_REQUEST_LINE:
        writer.write(b"HTTP/1.1 414 URI Too Long\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return None

    headers: dict[str, str] = {}
    header_bytes = 0
    while True:
        try:
            hdr = await asyncio.wait_for(
                reader.readline(), timeout=HEADER_TIMEOUT,
            )
        except asyncio.TimeoutError:
            return None
        header_bytes += len(hdr)
        if header_bytes > MAX_HEADER_BYTES:
            writer.write(
                b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
            return None
        if hdr in (b"\r\n", b"\n", b""):
            if not hdr:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return None
            break
        # Parse "Name: value" (case-insensitive name, lowercased here)
        name, _, value = hdr.partition(b":")
        if not value:
            continue
        key = name.decode("iso-8859-1").strip().lower()
        text = value.decode("iso-8859-1").strip()
        if key in headers:
            if key in ("host", "content-length", "transfer-encoding"):
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return None
            text = headers[key] + (("; " if key == "cookie" else ", ") + text)
        headers[key] = text
    return data, headers


# ── Connection handler ─────────────────────────────────────────────────────

async def handle_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
) -> None:
    """Top-level dispatch: CONNECT → tunnel, anything else → HTTP forward."""
    try:
        head = await _read_request_headers(reader, writer)
        if head is None:
            return
        request_line, headers = head

        line = request_line.decode("iso-8859-1").strip()
        parts = line.split()
        if len(parts) < 2:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        method = parts[0].upper()
        target = parts[1]

        if method == "CONNECT":
            await _handle_connect(reader, writer, target, headers)
        else:
            # GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD — all forwarded.
            # `target` may be absolute ("http://host/path") for proxy requests,
            # or origin-form ("/path") for direct requests to the proxy. We
            # only support proxy-style requests on this port.
            if not (target.startswith("http://") or target.startswith("https://")):
                writer.write(
                    b"HTTP/1.1 400 Bad Request\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                await writer.drain()
                return
            await _handle_http_forward(
                reader, writer, request_line, headers,
            )
    except (ConnectionError, OSError, asyncio.TimeoutError) as e:
        logger.debug("Connection error: %s", e)
    except Exception:
        logger.exception("Unexpected error in connection handler")
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── CONNECT (tunnel) handler ───────────────────────────────────────────────

async def _handle_connect(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    target: str, _headers: dict[str, str],
) -> None:
    """Tunnel raw bytes to host:port via DIRECT or upstream proxy."""
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

    route = await get_route(host)
    if route is None:
        writer.write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
        await writer.drain()
        return

    upstream = _select_proxy_url() if route == "PROXY" else None

    # Open the upstream connection with budgeted failover across upstreams
    # of the chosen type. For DIRECT we just open one socket.
    try:
        if upstream is not None:
            scheme, candidates = upstream
            upstream_reader, upstream_writer, chosen = await _connect_with_failover(
                host, port, scheme, candidates,
            )
        else:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, family=socket.AF_INET),
                timeout=CONNECT_TIMEOUT,
            )
            chosen = "DIRECT"
    except (OSError, ConnectionError, ValueError, asyncio.TimeoutError) as e:
        logger.warning("Connect failed: %s:%d -> %s: %s", host, port, route, e)
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await writer.drain()
        return

    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    logger.info("Tunnel established: %s:%d -> %s", host, port, chosen)

    task_a = asyncio.create_task(_pipe(reader, upstream_writer))
    task_b = asyncio.create_task(_pipe(upstream_reader, writer))
    _, pending = await asyncio.wait(
        [task_a, task_b], return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()
    await asyncio.gather(task_a, task_b, return_exceptions=True)
    logger.info("Tunnel closed: %s:%d", host, port)


async def _open_upstream_stream(
    host: str, port: int, scheme: str, proxy_host: str, proxy_port: int,
    *, forward_http: bool = False,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
    """Open a raw stream to host:port via the given upstream.

    Used for CONNECT, HTTP forwarding, and WebSocket upgrades.

    Returns (reader, writer, "scheme://host:port") for logging.
    """
    if scheme in ("socks5", "socks5h"):
        reader, writer = await _socks5_connect(host, port, proxy_host, proxy_port)
    elif scheme == "http" and forward_http:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    elif scheme in ("http", "https"):
        reader, writer = await _http_proxy_connect(host, port, proxy_host, proxy_port)
    else:
        raise ValueError(f"unsupported proxy scheme: {scheme!r}")
    return reader, writer, f"{scheme}://{proxy_host}:{proxy_port}"


async def _connect_with_failover(
    host: str, port: int, scheme: str,
    candidates: list[tuple[str, int]],
    *, forward_http: bool = False,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
    """Open a stream via one of the upstreams, with budgeted failover.

    Tries candidates in a fresh randomized order on every call (uniform
    random, not sticky — favors load-spread over connection reuse for
    short-lived tunnels/forwards). On per-attempt connect failure
    (OSError or per-attempt timeout) advances to the next candidate.

    Budgeting: the outer CONNECT_TIMEOUT bounds the *total* time across all
    attempts. Each attempt is given `remaining / candidates_left` so a
    stalled/blackholed first upstream cannot consume the whole budget and
    starve the healthy backups — without this, one silently-dropped SYN
    makes load-balancing unreliable whenever a backend is blackholed
    rather than failing fast.

    Returns (reader, writer, "scheme://host:port") describing the upstream
    that succeeded.
    """
    if not candidates:
        raise ValueError(f"no upstream configured for type={scheme!r}")
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
        slice_budget = (deadline - now) / (remaining_candidates + 1)
        tried.append(f"{ph}:{pp}")
        try:
            coro = _open_upstream_stream(
                host, port, scheme, ph, pp, forward_http=forward_http,
            )
            reader, writer, chosen = await asyncio.wait_for(
                coro, timeout=slice_budget,
            )
            return reader, writer, chosen
        except (OSError, ConnectionError, ValueError,
                asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            last_err = e
            logger.debug(
                "Upstream %s://%s:%s failed for %s:%d: %s",
                scheme, ph, pp, host, port, e,
            )
            continue
    raise ConnectionError(
        f"all upstreams failed for {host}:{port} "
        f"(tried {tried}, last error: {last_err})"
    )


async def _socks5_connect(
    host: str, port: int, proxy_host: str, proxy_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to host:port through a SOCKS5 proxy. Returns (reader, writer)."""
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await reader.readexactly(2)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise ValueError(f"SOCKS5 handshake failed: {resp.hex()}")

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            host_bytes = host.encode("idna")
            if len(host_bytes) > 255:
                raise ValueError("SOCKS5 destination hostname is too long")
            encoded_host = b"\x03" + bytes([len(host_bytes)]) + host_bytes
        else:
            encoded_host = (
                b"\x01" if address.version == 4 else b"\x04"
            ) + address.packed
        req = b"\x05\x01\x00" + encoded_host + port.to_bytes(2, "big")
        writer.write(req)
        await writer.drain()

        resp = await reader.readexactly(4)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise ValueError(
                f"SOCKS5 connect failed for {host}:{port}: {resp.hex()}"
            )
        atype = resp[3]
        if atype == 0x01:
            await reader.readexactly(6)
        elif atype == 0x03:
            dlen = (await reader.readexactly(1))[0]
            await reader.readexactly(dlen + 2)
        elif atype == 0x04:
            await reader.readexactly(18)
        else:
            raise ValueError(f"SOCKS5 returned unknown address type: {atype}")
    except BaseException:
        try:
            writer.close()
        except Exception:
            pass
        raise
    return reader, writer


async def _http_proxy_connect(
    host: str, port: int, proxy_host: str, proxy_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to host:port through an HTTP CONNECT proxy."""
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    try:
        authority = _host_header(host, port)
        req = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        resp = await reader.readline()
        parts = resp.decode("iso-8859-1", errors="replace").split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) != 200:
            raise ValueError(
                f"HTTP proxy connect failed for {host}:{port}: "
                f"{resp.decode().strip()}"
            )
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
    except BaseException:
        try:
            writer.close()
        except Exception:
            pass
        raise
    return reader, writer


# ── HTTP forward handler ───────────────────────────────────────────────────

def _host_header(host: str, port: int, default_port: int | None = None) -> str:
    authority = f"[{host}]" if ":" in host else host
    return authority if port == default_port else f"{authority}:{port}"


def _hop_headers(headers: dict[str, str]) -> set[str]:
    return set(_HOP_BY_HOP) | {
        token.strip().lower()
        for token in headers.get("connection", "").split(",")
        if token.strip()
    }


async def _handle_http_forward(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    request_line: bytes, headers: dict[str, str],
) -> None:
    """Forward an HTTP request to origin (DIRECT or via upstream proxy).

    Single-request scope: open one raw stream, send the request, relay the
    response. We do not parse the response body beyond what HTTP needs
    (Content-Length, chunked, or read-until-EOF for connection-close).
    No pipelining, no keep-alive to origin.
    """
    try:
        method, url, _ = request_line.decode("iso-8859-1").strip().split(" ", 2)
    except ValueError:
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return
    method = method.upper()

    # Parse origin host:port from the absolute URL.
    try:
        parts = urlsplit(url)
        parsed_port = parts.port
        port = parsed_port if parsed_port is not None else 80
    except ValueError:
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return

    if not parts.hostname or parts.scheme != "http" or not 1 <= port <= 65535:
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return

    host = parts.hostname

    route = await get_route(host)
    if route is None:
        writer.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        return

    upstream = _select_proxy_url() if route == "PROXY" else None

    is_upgrade = (
        headers.get("upgrade", "").lower() == "websocket"
        and "upgrade" in {
            token.strip().lower()
            for token in headers.get("connection", "").split(",")
        }
    )

    # WebSocket upgrades need a long-lived raw stream both ways — same
    # pattern as a CONNECT tunnel. Hand off to the upgrade handler.
    if is_upgrade:
        await _handle_websocket_upgrade(
            reader, writer, method, parts, headers, b"",
            upstream, host, port, route,
        )
        return

    MAX_BODY = 64 * 1024 * 1024
    body = b""
    has_content_length = "content-length" in headers
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    is_chunked = transfer_encoding == "chunked"
    if transfer_encoding and (not is_chunked or has_content_length):
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return

    cl_header = headers.get("content-length")
    cl = 0
    if cl_header is not None:
        if not re.fullmatch(r"[0-9]+", cl_header):
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        significant_digits = cl_header.lstrip("0") or "0"
        if len(significant_digits) > len(str(MAX_BODY)):
            cl = MAX_BODY + 1
        else:
            cl = int(significant_digits)
        if cl > MAX_BODY:
            writer.write(b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
    expectation = headers.get("expect", "").lower()
    if expectation and expectation != "100-continue":
        writer.write(b"HTTP/1.1 417 Expectation Failed\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return
    if expectation:
        writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        await writer.drain()

    try:
        if cl_header is not None:
            body = await asyncio.wait_for(
                reader.readexactly(cl), timeout=IDLE_TIMEOUT if IDLE_TIMEOUT > 0 else None,
            )
        elif is_chunked:
            body = await _read_chunked(reader, MAX_BODY)
    except asyncio.TimeoutError:
        logger.warning("Request body timeout: %s", host)
        writer.write(b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return
    except (asyncio.IncompleteReadError, _ChunkedDecodeError) as e:
        logger.warning("Invalid request body: %s: %s", host, e)
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return

    excluded = _hop_headers(headers) | {"expect"}
    forward_headers = {
        k: v for k, v in headers.items()
        if k not in excluded
    }
    forward_headers["host"] = _host_header(host, port, 80)
    # We close the upstream socket after relaying; tell the origin.
    forward_headers["connection"] = "close"

    # We always re-frame the body: the client may have sent chunked, the
    # origin may have a CL cap or just prefer CL. We drop the client's
    # Transfer-Encoding and set Content-Length from the decoded body.
    # (If the client didn't send a body, both are absent and that's fine.)
    if body or has_content_length or is_chunked:
        forward_headers.pop("transfer-encoding", None)
        forward_headers["content-length"] = str(len(body))

    path_and_query = parts.path or "/"
    if parts.query:
        path_and_query += "?" + parts.query
    if upstream is not None and upstream[0] == "http":
        path_and_query = f"http://{_host_header(host, port, 80)}{path_and_query}"

    # Open the raw connection (DIRECT or via upstream SOCKS5/HTTP-CONNECT),
    # with budgeted failover across configured upstreams of the chosen type.
    try:
        if upstream is not None:
            scheme, candidates = upstream
            upstream_reader, upstream_writer, chosen = await _connect_with_failover(
                host, port, scheme, candidates, forward_http=True,
            )
        else:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, family=socket.AF_INET),
                timeout=CONNECT_TIMEOUT,
            )
            chosen = "DIRECT"
    except (OSError, ConnectionError, ValueError, asyncio.TimeoutError) as e:
        logger.warning("Forward connect failed: %s -> %s: %s", host, route, e)
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        return

    # Send the request.
    try:
        lines = [f"{method} {path_and_query} HTTP/1.1"]
        for name, value in forward_headers.items():
            lines.append(f"{name}: {value}")
        lines.append("")
        lines.append("")
        upstream_writer.write(("\r\n".join(lines)).encode("iso-8859-1") + body)
        await upstream_writer.drain()
    except (ConnectionError, OSError) as e:
        logger.warning("Forward write failed: %s: %s", host, e)
        upstream_writer.close()
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        return

    # Relay the response. Read status line + headers, then body.
    try:
        await _relay_response(
            upstream_reader, writer, host, port, chosen, route, method,
        )
    finally:
        try:
            upstream_writer.close()
        except Exception:
            pass


async def _relay_response(
    upstream_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    host: str, port: int, chosen: str, route: str,
    method: str, status_line: bytes | None = None,
) -> None:
    """Relay interim responses and stream a final, connection-closing response."""
    while True:
        try:
            async with asyncio.timeout(RESPONSE_HEADER_TIMEOUT):
                if status_line is None:
                    status_line = await upstream_reader.readline()
                fields = status_line.split(None, 2)
                if (
                    len(fields) < 2 or fields[0] not in (b"HTTP/1.0", b"HTTP/1.1")
                    or not fields[1].isdigit()
                    or not 100 <= int(fields[1]) <= 599
                ):
                    raise ValueError("invalid upstream status line")
                status = int(fields[1])
                header_lines: list[tuple[str, bytes]] = []
                resp_headers: dict[str, str] = {}
                header_bytes = len(status_line)
                while True:
                    line = await upstream_reader.readline()
                    header_bytes += len(line)
                    if not line or header_bytes > MAX_HEADER_BYTES:
                        raise ValueError("incomplete or oversized upstream headers")
                    if line == b"\r\n":
                        break
                    name, separator, value = line.partition(b":")
                    if not separator:
                        raise ValueError("invalid upstream header")
                    lname = name.decode("iso-8859-1").lower()
                    text = value.decode("iso-8859-1").strip()
                    if lname in resp_headers and lname == "content-length":
                        raise ValueError("duplicate upstream Content-Length")
                    if lname in ("connection", "transfer-encoding") and lname in resp_headers:
                        text = resp_headers[lname] + ", " + text
                    resp_headers[lname] = text
                    header_lines.append((lname, line))

            if status == 101:
                raise ValueError("unexpected protocol upgrade")
            transfer_encoding = resp_headers.get("transfer-encoding", "")
            is_chunked = transfer_encoding.lower().split(",")[-1].strip() == "chunked"
            content_length = resp_headers.get("content-length")
            if content_length is not None and not re.fullmatch(r"[0-9]+", content_length):
                raise ValueError("invalid upstream Content-Length")
        except asyncio.TimeoutError:
            logger.warning("Upstream response header timeout: %s", host)
            client_writer.write(
                b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await client_writer.drain()
            return
        except ValueError as e:
            logger.warning("Invalid upstream response: %s: %s", host, e)
            client_writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await client_writer.drain()
            return

        excluded = _hop_headers(resp_headers)
        if transfer_encoding:
            excluded.add("content-length")
        client_writer.write(status_line)
        for name, line in header_lines:
            if name not in excluded:
                client_writer.write(line)
        if status < 200:
            client_writer.write(b"\r\n")
            await client_writer.drain()
            status_line = None
            continue

        if transfer_encoding and status not in (204, 304):
            client_writer.write(
                b"Transfer-Encoding: " + transfer_encoding.encode("iso-8859-1") + b"\r\n"
            )
        client_writer.write(b"Connection: close\r\n\r\n")
        await client_writer.drain()
        break

    logger.info("Forward: %s:%d -> %s via %s", host, port, route, chosen)
    if method == "HEAD" or status in (204, 304):
        return
    try:
        if is_chunked:
            async for chunk in _iter_chunked(upstream_reader):
                client_writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                await client_writer.drain()
            # Only emit successful completion after validating the entire input.
            client_writer.write(b"0\r\n\r\n")
            await client_writer.drain()
        elif content_length is not None and not transfer_encoding:
            await _relay_fixed_body(upstream_reader, client_writer, int(content_length))
        else:
            await _relay_until_eof(upstream_reader, client_writer)
    except (ConnectionError, OSError, asyncio.TimeoutError, _ChunkedDecodeError) as e:
        logger.warning("Response body relay failed: %s: %s", host, e)


async def _relay_fixed_body(
    upstream_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    content_length: int,
) -> None:
    """Relay exactly `content_length` bytes from upstream to client."""
    remaining = content_length
    while remaining > 0:
        chunk = await asyncio.wait_for(
            upstream_reader.read(min(65536, remaining)),
            timeout=IDLE_TIMEOUT if IDLE_TIMEOUT > 0 else None,
        )
        if not chunk:
            raise ConnectionError(f"upstream body ended with {remaining} bytes remaining")
        client_writer.write(chunk)
        await client_writer.drain()
        remaining -= len(chunk)


async def _relay_until_eof(
    upstream_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
) -> None:
    """Forward raw bytes from upstream to client until the socket closes."""
    while True:
        chunk = await asyncio.wait_for(
            upstream_reader.read(65536),
            timeout=IDLE_TIMEOUT if IDLE_TIMEOUT > 0 else None,
        )
        if not chunk:
            return
        client_writer.write(chunk)
        await client_writer.drain()


class _ChunkedDecodeError(Exception):
    """Raised when a chunked body cannot be decoded."""


async def _iter_chunked(
    reader: asyncio.StreamReader, max_bytes: int | None = None,
) -> AsyncIterator[bytes]:
    """Decode chunks in bounded pieces, validating framing and discarding trailers."""
    total = 0
    timeout = IDLE_TIMEOUT if IDLE_TIMEOUT > 0 else None
    try:
        while True:
            size_line = await asyncio.wait_for(
                reader.readline(), timeout=timeout,
            )
            size_text = size_line[:-2].split(b";", 1)[0]
            if (
                not size_line.endswith(b"\r\n") or len(size_line) > MAX_REQUEST_LINE
                or not re.fullmatch(rb"[0-9a-fA-F]+", size_text)
            ):
                raise _ChunkedDecodeError("invalid or missing chunk size")
            size = int(size_text, 16)
            if max_bytes is not None and total + size > max_bytes:
                raise _ChunkedDecodeError("chunked body exceeds size limit")
            if size == 0:
                trailer_bytes = 0
                while True:
                    line = await asyncio.wait_for(
                        reader.readline(), timeout=timeout,
                    )
                    trailer_bytes += len(line)
                    if not line.endswith(b"\r\n") or trailer_bytes > MAX_HEADER_BYTES:
                        raise _ChunkedDecodeError("incomplete or oversized trailers")
                    if line == b"\r\n":
                        return
                    if b":" not in line:
                        raise _ChunkedDecodeError("invalid trailer")
            remaining = size
            while remaining:
                data = await asyncio.wait_for(
                    reader.read(min(65536, remaining)), timeout=timeout,
                )
                if not data:
                    raise _ChunkedDecodeError("unexpected EOF in chunk data")
                remaining -= len(data)
                total += len(data)
                yield data
            if await asyncio.wait_for(reader.readexactly(2), timeout=timeout) != b"\r\n":
                raise _ChunkedDecodeError("missing chunk CRLF")
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError) as e:
        raise _ChunkedDecodeError(f"incomplete chunked body: {e}") from e


async def _handle_websocket_upgrade(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    method: str,
    parts: SplitResult,
    headers: dict[str, str], body: bytes,
    upstream: tuple[str, list[tuple[str, int]]] | None,
    host: str, port: int, route: str,
) -> None:
    """Handle a WebSocket upgrade by re-issuing the request over a raw socket.

    Opens a fresh raw connection (DIRECT or via the same upstream as a
    normal request), replays the request bytes, and on a 101 response
    pipes both ways. On any other status, relays the response back as a
    normal HTTP response and closes.
    """
    logger.info("WebSocket upgrade: %s:%d -> %s", host, port, route)

    try:
        if upstream is not None:
            scheme, candidates = upstream
            upstream_reader, upstream_writer, chosen = await _connect_with_failover(
                host, port, scheme, candidates, forward_http=True,
            )
        else:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, family=socket.AF_INET),
                timeout=CONNECT_TIMEOUT,
            )
            chosen = "DIRECT"
    except (OSError, ConnectionError, ValueError, asyncio.TimeoutError) as e:
        logger.warning("WebSocket upstream connect failed: %s -> %s: %s", host, route, e)
        client_writer.write(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
        )
        await client_writer.drain()
        return

    path_and_query = parts.path or "/"
    if parts.query:
        path_and_query += "?" + parts.query
    if upstream is not None and upstream[0] == "http":
        path_and_query = f"http://{_host_header(host, port, 80)}{path_and_query}"

    excluded = _hop_headers(headers)
    forward_headers = {
        k: v for k, v in headers.items() if k not in excluded
    }
    forward_headers["connection"] = "Upgrade"
    forward_headers["upgrade"] = "websocket"
    forward_headers["host"] = _host_header(host, port, 80)

    lines = [f"{method} {path_and_query} HTTP/1.1"]
    for name, value in forward_headers.items():
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append("")
    request_bytes = ("\r\n".join(lines)).encode("iso-8859-1") + body

    try:
        upstream_writer.write(request_bytes)
        await upstream_writer.drain()
    except (ConnectionError, OSError) as e:
        logger.warning("WebSocket upstream write failed: %s: %s", host, e)
        client_writer.write(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
        )
        await client_writer.drain()
        upstream_writer.close()
        return

    # Read the upstream response status line + headers, looking for 101.
    try:
        status_line = await asyncio.wait_for(
            upstream_reader.readline(), timeout=RESPONSE_HEADER_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.warning("WebSocket upstream status timeout: %s", host)
        client_writer.write(
            b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n"
        )
        await client_writer.drain()
        upstream_writer.close()
        return

    if not status_line:
        client_writer.write(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
        )
        await client_writer.drain()
        upstream_writer.close()
        return

    try:
        parts_status = status_line.decode("iso-8859-1").strip().split(" ", 2)
        status_code = (
            int(parts_status[1])
            if len(parts_status) >= 2 and parts_status[1].isdigit()
            else 0
        )
    except (ValueError, IndexError):
        status_code = 0

    if status_code != 101:
        logger.debug("WebSocket upgrade rejected: %s -> %d", host, status_code)
        try:
            await _relay_response(
                upstream_reader, client_writer, host, port, chosen, route,
                method, status_line,
            )
        finally:
            upstream_writer.close()
        return

    # 101 — relay status line + headers to the client, then pipe bytes.
    try:
        client_writer.write(status_line)
        while True:
            line = await asyncio.wait_for(
                upstream_reader.readline(), timeout=RESPONSE_HEADER_TIMEOUT,
            )
            client_writer.write(line)
            if line in (b"\r\n", b"\n", b""):
                break
        await client_writer.drain()
    except (ConnectionError, OSError, asyncio.TimeoutError) as e:
        logger.warning("WebSocket response relay failed: %s: %s", host, e)
        upstream_writer.close()
        return

    logger.info("WebSocket established: %s:%d -> %s", host, port, chosen)
    task_a = asyncio.create_task(_pipe(client_reader, upstream_writer))
    task_b = asyncio.create_task(_pipe(upstream_reader, client_writer))
    _, pending = await asyncio.wait(
        [task_a, task_b], return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()
    await asyncio.gather(task_a, task_b, return_exceptions=True)
    logger.info("WebSocket closed: %s:%d", host, port)


async def _read_chunked(
    reader: asyncio.StreamReader, max_bytes: int,
) -> bytes:
    """Buffer a validated request body within the upload limit."""
    buf = bytearray()
    async for chunk in _iter_chunked(reader, max_bytes):
        buf.extend(chunk)
    return bytes(buf)


# Headers that should not be forwarded by an HTTP proxy.
# Per RFC 7230 §6.1.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
    # "proxy-connection" is non-standard but common; strip for safety.
    "proxy-connection",
})

# ── Server lifecycle ───────────────────────────────────────────────────────

async def start(host: str = "0.0.0.0",
                port: int = 8888,
                ready_event: asyncio.Event | None = None) -> None:
    """Start the HTTP/CONNECT proxy server.

    Blocks until the server is stopped (call from a task).
    """
    # Initial rules load — retry until available
    while not _rules_loaded:
        if refresh_rules():
            break
        logger.info("Waiting for PAC rules to be seeded...")
        await asyncio.sleep(2)

    server = await asyncio.start_server(handle_connection, host, port)

    async def refresh_periodically() -> None:
        while True:
            await asyncio.sleep(RULE_REFRESH_INTERVAL)
            try:
                refresh_rules()
            except Exception:
                logger.exception("Failed to refresh proxy rules")

    refresh_task = None
    if RULE_REFRESH_INTERVAL > 0:
        refresh_task = asyncio.create_task(refresh_periodically())

    if ready_event is not None:
        ready_event.set()

    logger.info(
        "Proxy listening on %s:%d (%d direct, %d proxy, default=%s)",
        host, port, len(_direct_set), len(_proxy_set), _default_route,
    )

    try:
        async with server:
            await server.serve_forever()
    finally:
        if refresh_task is not None:
            refresh_task.cancel()
            await asyncio.gather(refresh_task, return_exceptions=True)
