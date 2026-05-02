"""
Network Operations Module

Handles network fragmentation and hashing operations
for optimizing IP lookup performance in PAC files.
"""

import ipaddress
from typing import List


def fregment_net(net: ipaddress.IPv4Network, mask_step: int = 2) -> List[ipaddress.IPv4Network]:
    """Fragment a network into subnets aligned to mask_step boundaries."""
    target_prefixlen = (net.prefixlen - 1) // mask_step * mask_step + mask_step
    try:
        return list(net.subnets(new_prefix=target_prefixlen))
    except ValueError:
        return [net]


def fregment_nets(nets: List[ipaddress.IPv4Network], mask_step: int = 2) -> List[ipaddress.IPv4Network]:
    """Fragment multiple networks into subnets aligned to mask_step boundaries."""
    results = []
    for net in nets:
        results.extend(fregment_net(net, mask_step))
    return results


def hash_address(address: ipaddress.IPv4Address, mod_base: int) -> int:
    """Hash an IP address using modulo operation."""
    return int(address) % mod_base


def hash_nets(nets: List[ipaddress.IPv4Network], mod_base: int) -> List[List[ipaddress.IPv4Network]]:
    """Distribute networks into hash buckets based on their network address."""
    hashed = [[] for _ in range(mod_base)]
    for net in nets:
        bucket_index = hash_address(net.network_address, mod_base)
        hashed[bucket_index].append(net)
    return hashed


def calculate_prefix_range(networks: List[ipaddress.IPv4Network]) -> tuple:
    """Calculate the min and max prefix lengths in a network list."""
    if not networks:
        return (32, 0)
    return (min(net.prefixlen for net in networks),
            max(net.prefixlen for net in networks))
