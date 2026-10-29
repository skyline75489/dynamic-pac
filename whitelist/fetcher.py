"""
Fetch domain whitelist from felixonmars/dnsmasq-china-list.

The list is in dnsmasq format:
    server=/<domain>/114.114.114.114

We extract domains, filter out wildcard-only entries, and return a sorted list.
"""

import logging
import re

import httpx

logger = logging.getLogger("dynamic-pac.whitelist")

WHITELIST_URL = (
    "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/"
    "master/accelerated-domains.china.conf"
)

_DOMAIN_RE = re.compile(r"(?<==/).+?(?=/)")

# Domains to skip (wildcard-only, not useful for PAC matching)
_SKIP_PATTERNS = re.compile(
    r"(^|\.)\*\.|"  # wildcard domains like *.example.com
    r"\.\*$|"  # trailing wildcard
    r"^\*$"  # bare asterisk
)


def fetch_domain_list(proxy: str | None = None) -> list[str]:
    """Fetch and parse the domain whitelist from dnsmasq-china-list.

    Returns a sorted list of unique domain strings.
    """
    kwargs: dict = {"timeout": 30.0}
    if proxy:
        kwargs["proxy"] = proxy

    with httpx.Client(**kwargs) as client:
        response = client.get(WHITELIST_URL)
        response.raise_for_status()
        text = response.text

    domains: set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _DOMAIN_RE.findall(line)
        if match:
            domain = match[0].strip()
            if domain and not _SKIP_PATTERNS.search(domain):
                domains.add(domain)

    result = sorted(domains)
    logger.info(
        "Fetched %d domains from dnsmasq-china-list (%d raw lines)",
        len(result),
        len(text.splitlines()),
    )
    return result
