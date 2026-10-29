"""
Tailnet-aware proxy selection for served PAC files.

Some deployments run the upstream proxy on a private network (e.g. a
Tailscale tailnet) and want clients that are themselves on that network
to reach it over the private address instead of the public one.

Two mechanisms work together:

A. Server-side (exact)
   The HTTP client that fetched the PAC is known to this server
   (``request.client.host``).  If that address is inside one of the
   configured tailnet CIDRs, the PAC is rendered with the alternative
   proxy chain (``PAC_PROXY_TS_ALT``) baked in.

B. Client-side (dynamic)
   The PAC carries a small runtime that evaluates ``myIpAddress()`` on
   *every* request and switches to the alternative chain when the client
   itself is on the tailnet.  This covers clients that fetched the PAC
   over a non-tailnet address but joined the tailnet later.

Both mechanisms are no-ops unless ``PAC_PROXY_TS_ALT`` is configured.
"""

import ipaddress
import json
import logging
import os
import re

logger = logging.getLogger("dynamic-pac.runtime")

# Environment variables
ALT_PROXY_ENV = "PAC_PROXY_TS_ALT"
TS_CIDRS_ENV = "TS_CLIENT_CIDRS"
TS_PASSTHROUGH_ENV = "TS_PASSTHROUGH_ENABLED"
DEFAULT_TS_CIDRS = ["100.64.0.0/10"]

# `function FindProxyForURL(url, host) { ... }`
_FIND_PROXY_FUNC_RE = re.compile(r"function\s+FindProxyForURL\s*\(")
# `var FindProxyForURL = function(url, host) { ... }`
_FIND_PROXY_ASSIGN_RE = re.compile(r"(FindProxyForURL\s*=\s*function\s*\()")

_ORIGINAL_NAME = "__dpOriginalFindProxyForURL"

# Runtime injected into the served PAC.  Placeholders are substituted
# with .replace() so the JS body needs no brace escaping.
_RUNTIME_TEMPLATE = """
// --- dynamic-pac: tailnet-aware proxy selection ---
var __dpAltProxy = __DP_ALT_PROXY__;
var __dpServerTailnet = __DP_SERVER_TAILNET__;
var __dpTsCidrs = [__DP_TS_CIDRS__];

function __dpIpToInt(ip) {
    var parts = ip.split('.'), i, n, v = 0;
    if (parts.length !== 4) return -1;
    for (i = 0; i < 4; i++) {
        n = parseInt(parts[i], 10);
        if (isNaN(n) || n < 0 || n > 255) return -1;
        v = v * 256 + n;
    }
    return v;
}

function __dpInCidr(ip, netInt, prefix) {
    var v = __dpIpToInt(ip);
    if (v < 0) return false;
    if (prefix <= 0) return true;
    var size = Math.pow(2, 32 - prefix);
    return Math.floor(v / size) === Math.floor(netInt / size);
}

function __dpIsTailnetClient() {
    var ip, i;
    if (typeof myIpAddress !== 'function') return false;
    try { ip = myIpAddress(); } catch (e) { return false; }
    if (!ip || ip.indexOf(':') >= 0) return false;
    for (i = 0; i < __dpTsCidrs.length; i++) {
        if (__dpInCidr(ip, __dpTsCidrs[i][0], __dpTsCidrs[i][1])) return true;
    }
    return false;
}

function __dpApplyAltProxy(result) {
    if (!__dpAltProxy) return result;
    // Leave DIRECT decisions alone — only proxy chains are swapped.
    if (!result || !/(PROXY|SOCKS)/i.test(result)) return result;
    if (__dpServerTailnet) return __dpAltProxy;
    return __dpIsTailnetClient() ? __dpAltProxy : result;
}
"""

# Wrapper installed after the original FindProxyForURL has been renamed.
_WRAPPER = """
function FindProxyForURL(url, host) {
    var __dpResult = __dpOriginalFindProxyForURL(url, host);
    return __dpApplyAltProxy(__dpResult);
}
"""


def get_alt_proxy() -> str:
    """The alternative proxy chain (empty when the feature is disabled)."""
    return os.getenv(ALT_PROXY_ENV, "").strip()


def ts_passthrough_enabled() -> bool:
    """True when the Tailscale passthrough rule is active.

    The ``.ts.net`` -> DIRECT rule is opt-in: it only applies when at
    least one Tailscale environment variable is present
    (``TS_PASSTHROUGH_ENABLED``, ``PAC_PROXY_TS_ALT`` or
    ``TS_CLIENT_CIDRS``).
    """
    flag = os.getenv(TS_PASSTHROUGH_ENV, "").strip().lower()
    if flag in ("1", "true", "yes", "on"):
        return True
    if get_alt_proxy():
        return True
    if get_ts_cidrs_raw():
        return True
    return False


def ts_direct_check_js() -> str:
    """JS snippet that routes Tailscale MagicDNS hosts to DIRECT.

    Returns an empty string when Tailscale support is not configured, so
    the generated PAC stays untouched.
    """
    if not ts_passthrough_enabled():
        return ""
    return "    if (/(^|\\.)ts\\.net$/.test(host)) {\n        return 'DIRECT';\n    }\n\n"


def get_ts_cidrs_raw() -> list[str]:
    """The configured client CIDRs as a list of strings.

    ``TS_CLIENT_CIDRS`` accepts either a JSON list
    (``["100.64.0.0/10", "10.0.0.0/8"]``) or a comma-separated list
    (``100.64.0.0/10,10.0.0.0/8``).  Returns an empty list when unset.
    """
    raw = os.getenv(TS_CIDRS_ENV, "").strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
        except ValueError:
            logger.warning("Ignoring invalid JSON in %s", TS_CIDRS_ENV)
            return []
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
        logger.warning("%s must contain a JSON list", TS_CIDRS_ENV)
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def get_ts_cidrs() -> list:
    """The IPv4 client ranges considered to be "tailnet" clients."""
    nets = []
    for part in get_ts_cidrs_raw():
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            logger.warning("Ignoring invalid %s entry: %r", TS_CIDRS_ENV, part)
            continue
        if net.version != 4:
            logger.warning("%s supports IPv4 ranges only, ignoring %r", TS_CIDRS_ENV, part)
            continue
        nets.append(net)
    if not nets:
        nets.append(ipaddress.ip_network(DEFAULT_TS_CIDRS[0]))
    return nets


def is_tailnet_ip(ip: str | None) -> bool:
    """True when the address is inside one of the configured tailnet CIDRs."""
    if not ip:
        return False
    ip = ip.strip()
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6:
        if not addr.ipv4_mapped:
            return False
        addr = addr.ipv4_mapped
    return any(addr in net for net in get_ts_cidrs())


def select_proxy_chain(client_ip: str | None, primary: str, alternate: str) -> tuple[str, bool]:
    """Pick the proxy chain to bake into the PAC for a requesting client.

    Returns ``(chain, server_tailnet)``.  Clients seen inside the
    tailnet CIDRs get the alternate chain; everyone else gets the
    primary one.
    """
    if not alternate:
        return primary, False
    if is_tailnet_ip(client_ip):
        return alternate, True
    return primary, False


def apply_alt_proxy_runtime(content: str, alt_proxy: str, server_tailnet: bool = False) -> str:
    """Wrap FindProxyForURL so tailnet clients use the alternate chain.

    The original function is renamed and a thin wrapper is appended that
    swaps proxy chains (never DIRECT decisions) for the alternate chain
    when the client is on the tailnet.
    """
    if not alt_proxy:
        return content
    if _ORIGINAL_NAME in content:
        return content  # already injected — keep it idempotent

    if _FIND_PROXY_FUNC_RE.search(content):
        content = _FIND_PROXY_FUNC_RE.sub(
            f"function {_ORIGINAL_NAME}(",
            content,
            count=1,
        )
    elif _FIND_PROXY_ASSIGN_RE.search(content):
        content = _FIND_PROXY_ASSIGN_RE.sub(
            f"{_ORIGINAL_NAME} = function(",
            content,
            count=1,
        )
    else:
        logger.warning("FindProxyForURL not found — alt proxy runtime not injected")
        return content

    cidrs = ", ".join(f"[{int(net.network_address)}, {net.prefixlen}]" for net in get_ts_cidrs())
    runtime = (
        _RUNTIME_TEMPLATE.replace("__DP_ALT_PROXY__", json.dumps(alt_proxy))
        .replace("__DP_SERVER_TAILNET__", "true" if server_tailnet else "false")
        .replace("__DP_TS_CIDRS__", cidrs)
    )
    return f"{content.rstrip()}\n{runtime}{_WRAPPER}"
