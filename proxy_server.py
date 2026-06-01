"""
HTTP CONNECT proxy for dynamic-pac.

Parses PAC rules and routes connections through SOCKS5/HTTP upstream
or directly based on domain matching.

Started as a separate TCP server alongside the FastAPI app.
"""

import asyncio
import logging
import re

from gfwlist.provider import get_rules

logger = logging.getLogger("dynamic-pac.proxy")

# Regexes to parse the PAC_PROXY string
_SOCKS_RE = re.compile(r"SOCKS5?\s+([^:\s]+):(\d+)", re.I)
_HTTP_RE = re.compile(r"PROXY\s+([^:\s]+):(\d+)", re.I)

# ---------------------------------------------------------------------------
# Cached routing state
# ---------------------------------------------------------------------------
_whitelist: set[str] = set()
_blocklist: set[str] = set()
_upstream: dict[str, tuple[str, int]] = {}  # {"socks5": (host, port), "http": ...}
_rules_loaded = False


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


def _build_domain_sets(rules: list) -> tuple[set[str], set[str]]:
    """Build whitelist and blocklist sets from a parsed PAC rules array.

    In the PAC: rules[tier][sub_idx] where sub_idx % 2 == 0 → DIRECT,
    sub_idx % 2 == 1 → PROXY.
    """
    whitelist: set[str] = set()
    blocklist: set[str] = set()
    for tier in rules:
        for sub_idx, sublist in enumerate(tier):
            for domain in sublist:
                if sub_idx % 2 == 0:
                    whitelist.add(domain)
                else:
                    blocklist.add(domain)
    return whitelist, blocklist


def refresh_rules() -> bool:
    """Fetch latest rules from the gfwlist provider and rebuild routing state.

    Returns True if rules were updated, False if not yet available.
    """
    global _whitelist, _blocklist, _upstream, _rules_loaded

    data = get_rules()
    if data is None:
        return False

    whitelist, blocklist = _build_domain_sets(data["rules"])
    upstream = _parse_proxy_config(data["proxy"])

    _whitelist = whitelist
    _blocklist = blocklist
    _upstream = upstream
    _rules_loaded = True

    logger.info(
        "Rules refreshed: %d whitelist, %d blocklist entries, %d upstream proxies",
        len(whitelist), len(blocklist), len(upstream),
    )
    return True


# ── Host matching ──────────────────────────────────────────────────────────

def get_route(host: str) -> str | None:
    """Determine routing for a host.

    Returns 'DIRECT' or 'PROXY', or None if rules aren't loaded yet.
    """
    if not _rules_loaded:
        return None

    if _match_domain(host, _whitelist):
        return "DIRECT"
    if _match_domain(host, _blocklist):
        return "PROXY"
    # Default: DIRECT (anything not in any list goes direct)
    return "DIRECT"


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

    logger.info("CONNECT proxy listening on %s:%d (%d whitelist, %d blocklist)",
                host, port, len(_whitelist), len(_blocklist))

    async with server:
        await server.serve_forever()
