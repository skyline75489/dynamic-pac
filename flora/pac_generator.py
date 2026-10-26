"""
PAC File Generation Module

Generates PAC file content with embedded JavaScript hash tables.
The proxy line uses a placeholder ('__PROXY_PLACEHOLDER__') so the
generated content can be cached and proxy injected at serving time.
"""

import ipaddress
from typing import List

from .ip_data import merge_all
from .network_ops import fregment_nets, hash_nets, calculate_prefix_range
from pac_runtime import ts_direct_check_js

PROXY_PLACEHOLDER = '__PROXY_PLACEHOLDER__'


def generate_balanced_proxy_js(proxies: List[str], balance: str) -> str:
    """Generate JavaScript code for proxy selection."""
    if balance == 'no':
        return "return '%s' ;" % (';'.join(proxies))
    elif balance == 'local_ip':
        return (
            "  var local_ip_balance = function(proxies) {\n"
            "    var i, k, l, myseg, s, _i;\n"
            "    myseg = parseInt(myIpAddress().split(\".\")[3]);\n"
            "    l = proxies.length;\n"
            "    k = myseg %% l;\n"
            "    s = '';\n"
            "    for (i = _i = 0; 0 <= l ? _i < l : _i > l; i = 0 <= l ? ++_i : --_i) {\n"
            "      s += proxies[(k + i) %% l];\n"
            "    }\n"
            "    return s;\n"
            "  };\n"
            + "  return local_ip_balance([%s]);\n" % (
                ','.join("'%s'" % p for p in proxies))
        )
    elif balance == 'host':
        return (
            "  var target_host_balance = function(proxies, host) {\n"
            "    var hash_string, i, k, l, s, _i;\n"
            "    hash_string = function(s) {\n"
            "      var c, hash, _i, _len;\n"
            "      hash = 0;\n"
            "      for (_i = 0, _len = s.length; _i < _len; _i++) {\n"
            "        c = s[_i];\n"
            "        hash = (hash << 5) - hash + c.charCodeAt(0);\n"
            "        hash = hash & hash & 0xFFFF;\n"
            "        hash &= 0xFFFF;\n"
            "      }\n"
            "      return hash;\n"
            "    };\n"
            "    l = proxies.length;\n"
            "    k = hash_string(host) %% l;\n"
            "    s = '';\n"
            "    for (i = _i = 0; 0 <= l ? _i < l : _i > l; i = 0 <= l ? ++_i : --_i) {\n"
            "      s += proxies[(k + i) %% l];\n"
            "    }\n"
            "    return s;\n"
            "  };\n"
            + "  return target_host_balance([%s], host);\n" % (
                ','.join("'%s'" % p for p in proxies))
        )
    return "return 'DIRECT';"


def generate_no_proxy_js(no_proxy: List[str]) -> str:
    """Generate JavaScript condition code for no-proxy rules."""
    s = ''
    for n in no_proxy:
        try:
            ip = ipaddress.ip_address(n)
            s += " ip == '%s' ||" % n
            continue
        except ValueError:
            pass
        try:
            net = ipaddress.ip_network(n)
            s += " isInNet(ip, '%s', '%s') ||" % (net.network_address, net.netmask)
            continue
        except ValueError:
            pass
        s += " host == '%s' ||" % n
    return s


def generate_template_content(
    hashed_results,
    hash_base: int,
    mask_step: int,
    min_prefixlen: int,
    max_prefixlen: int,
    no_proxy: List[str],
) -> str:
    """
    Generate the complete PAC file content as a string, using PROXY_PLACEHOLDER
    for the proxy line so it can be injected at serving time.
    """
    # Header and JavaScript helper functions
    pac = """
// Flora_Pac by @leaskh
// www.leaskh.com, i@leaskh.com
// Optimized by @yaleh
  
function FindProxyForURL(url, host) {
  var HASH_BASE, MASK_STEP, a, dot2num, hash_masked_ip, hashed_nets, i, lookup_ip, max_prefixlen, min_prefixlen, num2dot, prefixlen2mask, rebuild_net, _i, _j, _len, _len1;

  dot2num = function(dot) {
    var d;
    d = dot.split(".");
    return ((((((+d[0]) * 256) + (+d[1])) * 256) + (+d[2])) * 256) + (+d[3]);
  };

  num2dot = function(ip) {
    return [ip >>> 24, ip >>> 16 & 0xFF, ip >>> 8 & 0xFF, ip & 0xFF].join(".");
  };

  hash_masked_ip = function(ip, mask_len, mod_base) {
    var i, net, offset, _i;
    offset = 32 - mask_len;
    net = ip >>> offset;
    for (i = _i = 0; 0 <= offset ? _i < offset : _i > offset; i = 0 <= offset ? ++_i : --_i) {
      net *= 2;
    }
    return net % mod_base;
  };

  prefixlen2mask = function(prefixlen) {
    var imask;
    imask = 0xFFFFFFFF << (32 - prefixlen);
    return (imask >> 24 & 0xFF) + '.' + (imask >> 16 & 0xFF) + '.' + (imask >> 8 & 0xFF) + '.' + (imask & 0xFF);
  };

  rebuild_net = function(pair) {
    var masks, result;
    result = ['', ''];
    result[0] = num2dot(pair[0] << (32 - pair[1]));
    result[1] = prefixlen2mask(pair[1]);
    return result;
  };

  lookup_ip = function(ip) {
    var i, k, len, n, n_ip, _i, _len, _ref;
    len = min_prefixlen;
    n_ip = dot2num(ip);
    while (len <= max_prefixlen) {
      k = hash_masked_ip(n_ip, len, HASH_BASE);
      _ref = hashed_nets[k];
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        i = _ref[_i];
        n = rebuild_net(i);
        if (isInNet(ip,n[0],n[1])) {
          return true;
        }
      }
      len += MASK_STEP;
    }
    return false;
  };
"""

    # Configuration constants
    pac += f"""
  HASH_BASE = {hash_base};
  MASK_STEP = {mask_step};
  min_prefixlen = {min_prefixlen};
  max_prefixlen = {max_prefixlen};

"""

    # Mask step variables
    for i in range(min_prefixlen, max_prefixlen + 1, mask_step):
        pac += f"    var m{i} = {i};\n"

    # Hashed networks data
    pac += "    var empty_array = [];\n"
    pac += "    var hashed_nets = [\n"

    for i in range(len(hashed_results)):
        if len(hashed_results[i]) > 0:
            pac += "\n        ["
            for net in hashed_results[i]:
                pac += f"\n            [{int(net.network_address) >> (32 - net.prefixlen)}, m{net.prefixlen}],"
            pac += "\n        ],"
        else:
            pac += "\n        empty_array,"

    pac += """
    ];

    if (isPlainHostName(host)
     || (host == '127.0.0.1')
     || (host == 'localhost')
     ) {
        return 'DIRECT';
    }

""" + ts_direct_check_js() + """
    var ip = dnsResolve(host);

    if (ip == null || ip == '' || """ + generate_no_proxy_js(no_proxy) + """ lookup_ip(ip)) {
        return 'DIRECT';
    }

    return '""" + PROXY_PLACEHOLDER + """' ;

}
"""
    return pac


def generate_pac_content_from_data(
    hashed_results,
    hash_base: int,
    mask_step: int,
    min_prefixlen: int,
    max_prefixlen: int,
    no_proxy: List[str] | None = None,
) -> str:
    """
    Generate PAC template from pre-processed hashed data.
    No APNIC fetch — data must already be fetched and hashed.

    The proxy line is left as __PROXY_PLACEHOLDER__ for
    serving-time injection.
    """
    if no_proxy is None:
        no_proxy = ['192.168.0.0/24']

    return generate_template_content(
        hashed_results,
        hash_base, mask_step,
        min_prefixlen, max_prefixlen,
        no_proxy,
    )


def generate_flora_content(
    hash_base: int = 3011,
    mask_step: int = 2,
    no_proxy: List[str] | None = None,
) -> str:
    """
    Fetch China IP data, build the hash table, and return a PAC template
    with the proxy line as __PROXY_PLACEHOLDER__.
    """
    import logging
    logger = logging.getLogger("dynamic-pac.flora")

    if no_proxy is None:
        no_proxy = ['192.168.0.0/24']

    logger.info("Fetching China IP ranges from APNIC...")
    results = merge_all(fetch_ip_data())
    logger.info("Fetched %d network ranges", len(results))

    min_prefixlen, max_prefixlen = calculate_prefix_range(results)
    logger.info("Prefix range: [%d, %d]", min_prefixlen, max_prefixlen)

    logger.info("Fragmenting and hashing networks...")
    hashed_results = hash_nets(fregment_nets(results, mask_step), hash_base)

    content = generate_pac_content_from_data(
        hashed_results,
        hash_base, mask_step,
        min_prefixlen, max_prefixlen,
        no_proxy,
    )

    # Stats
    none_empty_count = sum(1 for bucket in hashed_results if len(bucket) > 0)
    avg_len = float(len(results)) / none_empty_count if none_empty_count > 0 else 0
    steps = (max_prefixlen - min_prefixlen) / mask_step + 1
    logger.info(
        "Flora PAC generated: %d bytes, %d rules, "
        "avg match length %.2f, %d steps",
        len(content), len(results), avg_len, steps,
    )

    return content


# Late import to avoid circular deps during package init
from .ip_data import fetch_ip_data  # noqa: E402
