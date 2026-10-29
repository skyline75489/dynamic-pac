"""
PAC file generation for domain whitelist.

Generates a PAC file with an embedded domain whitelist as a JSON object.
Uses __PROXY_PLACEHOLDER__ for serving-time proxy injection.
"""

from pac_runtime import ts_passthrough_enabled

PROXY_PLACEHOLDER = "__PROXY_PLACEHOLDER__"


def generate_pac_content(domains: list[str]) -> str:
    """Generate a PAC file with the given domain whitelist.

    The proxy line uses PROXY_PLACEHOLDER so it can be injected at
    serving time.  All other logic is self-contained JavaScript.
    """

    # Build the domain whitelist as a JSON object (not JSON array)
    # so hasOwnProperty lookups are O(1).
    domain_json = "{\n" + "\n".join(f'"{d}":1,' for d in domains) + '\n"yourdomainhere.com":1\n}'

    # Tailscale MagicDNS is only special-cased when Tailscale support is
    # configured (see pac_runtime.ts_passthrough_enabled).
    ts_check = (
        ' || host.endsWith(".ts.net") || host == "ts.net"' if ts_passthrough_enabled() else ""
    )

    pac = f"""var proxy = '{PROXY_PLACEHOLDER}';
var direct = 'DIRECT';

var white_domains = {domain_json};

var subnetIp4RangeList = [
  0, 1,
  167772160, 184549376,
  2130706432, 2130706688,
  2886729728, 2887778304,
  3232235520, 3232301056
];

var subnetIp6RangeList = [
  [0x0, 0x0, 0x0, 0x0], [0x0, 0x0, 0x0, 0x2],
  [0xfe800000, 0x0, 0x0, 0x0], [0xfe800000, 0x1, 0x0, 0x0],
  [0xfec00000, 0x0, 0x0, 0x0], [0xfec00000, 0x10000, 0x0, 0x0],
];

var hasOwnProperty = Object.hasOwnProperty;

function check_ipv4(host) {{
    var re_ipv4 = /^\\d+\\.\\d+\\.\\d+\\.\\d+$/;
    return re_ipv4.test(host);
}}

function convertIp4Address(strIp) {{
    var bytes = strIp.split('.');
    var result = (bytes[0] << 24) |
        (bytes[1] << 16) |
        (bytes[2] << 8) |
        (bytes[3]);
    return result >>> 0;
}}

function isInIp4RangeList(ipRange, intIp) {{
    if (ipRange.length === 0)
        return false;
    var left = 0, right = ipRange.length - 1;
    do {{
        var mid = Math.floor((left + right) / 2);
        if (mid & 0x1) {{
            if (intIp >= ipRange[mid - 1]) {{
                if (intIp < ipRange[mid]) {{
                    return true
                }} else {{
                    left = mid + 1;
                }}
            }} else {{
                right = mid - 2
            }}
        }} else {{
            if (intIp >= ipRange[mid]) {{
                if (intIp < ipRange[mid + 1]) {{
                    return true;
                }} else {{
                    left = mid + 2;
                }}
            }} else {{
                right = mid - 1;
            }}
        }}
    }} while (left < right);
    return false;
}}

function getProxyFromIp4(strIp) {{
    var intIp = convertIp4Address(strIp);
    if (isInIp4RangeList(subnetIp4RangeList, intIp)) {{
        return direct;
    }}
    return proxy;
}}

function check_ipv6(host) {{
    var re_ipv6 = /^((?=.*::)(?!.*::.+::)(::)?([\\dA-F]{{1,4}}:(:|\\b)|){{5}}|([\\dA-F]{{1,4}}:){{6}})((([\\dA-F]{{1,4}}((?!\\3)::|:\\b|$))|(?!\\2\\3)){{2}})$/i;
    return re_ipv6.test(host)
}}

function convertIp6Address(strIp) {{
    var words = strIp.split(':');
    var pos = words.indexOf('');
    if (pos === 0)
        pos = words.indexOf('', pos + 1);
    var result = [0, 0, 0, 0];
    var len = words.length;
    var index = 0,
        wordi = 0;
    do {{
        if (pos === wordi) {{
            index += 9 - len;
        }} else {{
            var word = words[wordi];
            if (word) {{
                if (index & 0x1)
                    result[index >>> 1] += parseInt(word, 16);
                else
                    result[index >>> 1] = (parseInt(word, 16) << 16) >>> 0;
            }}
            index++;
        }}
        wordi++;
    }} while (wordi < len);
    return result;
}}

function compareIp6(a, b) {{
    if (a[0] > b[0]) return 1;
    if (a[0] < b[0]) return -1;
    if (a[1] > b[1]) return 1;
    if (a[1] < b[1]) return -1;
    if (a[2] > b[2]) return 1;
    if (a[2] < b[2]) return -1;
    if (a[3] > b[3]) return 1;
    if (a[3] < b[3]) return -1;
    return 0;
}}

function isInIp6RangeList(ipRange, intIp) {{
    if (ipRange.length === 0)
        return false;
    var left = 0, right = ipRange.length - 1;
    do {{
        var mid = Math.floor((left + right) / 2);
        if (mid & 0x1) {{
            if (compareIp6(intIp, ipRange[mid - 1]) >= 0) {{
                if (compareIp6(intIp, ipRange[mid]) < 0) {{
                    return true
                }} else {{
                    left = mid + 1;
                }}
            }} else {{
                right = mid - 2
            }}
        }} else {{
            if (compareIp6(intIp, ipRange[mid]) >= 0) {{
                if (compareIp6(intIp, ipRange[mid + 1]) < 0) {{
                    return true;
                }} else {{
                    left = mid + 2;
                }}
            }} else {{
                right = mid - 1;
            }}
        }}
    }} while (left < right);
    return false;
}}

function getProxyFromIp6(strIp) {{
    var intIp = convertIp6Address(strIp);
    if (isInIp6RangeList(subnetIp6RangeList, intIp)) {{
        return direct;
    }}
    return proxy;
}}

function isInDomains(domain_dict, host) {{
    var pos = host.lastIndexOf('.');
    var suffix = host.substring(pos + 1);
    if (suffix === "cn") {{
        return true;
    }}
    if (host.endsWith(".nip.io") || host.endsWith(".sslip.io") || host.endsWith(".traefik.me"){ts_check}) {{
        return true;
    }}
    pos = host.lastIndexOf('.', pos - 1);
    while (true) {{
        if (pos === -1) {{
            return hasOwnProperty.call(domain_dict, host);
        }}
        suffix = host.substring(pos + 1);
        if (hasOwnProperty.call(domain_dict, suffix)) {{
            return true;
        }}
        pos = host.lastIndexOf('.', pos - 1);
    }}
}}

function FindProxyForURL(url, host) {{
    if (isPlainHostName(host)
     || (host == '127.0.0.1')
     || (host == 'localhost')
     ) {{
        return direct;
    }}
    if (check_ipv4(host)) {{
        return getProxyFromIp4(host);
    }}
    if (check_ipv6(host)) {{
        return getProxyFromIp6(host);
    }}
    if (isInDomains(white_domains, host)) {{
        return direct;
    }}
    return proxy;
}}

// String.prototype.endsWith polyfill (for older browsers)
if (!String.prototype.endsWith) {{
    String.prototype.endsWith = function(searchString, position) {{
        var subjectString = this.toString();
        if (typeof position !== 'number' || !isFinite(position) || Math.floor(position) !== position || position > subjectString.length) {{
            position = subjectString.length;
        }}
        position -= searchString.length;
        var lastIndex = subjectString.indexOf(searchString, position);
        return lastIndex !== -1 && lastIndex === position;
    }};
}}
"""
    return pac
