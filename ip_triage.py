"""Offline IP classification. No network access or reputation claims."""

import argparse
import ipaddress
import json
import sys

DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def in_networks(address, networks):
    return any(address.version == network.version and address in network for network in networks)


def classify(value):
    if not isinstance(value, str) or "/" in value or "%" in value:
        raise ValueError("Enter one IPv4 or IPv6 address, without a subnet or zone identifier.")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("Invalid IP address.") from None

    if address.version == 6 and address.ipv4_mapped:
        scope = "ipv4-mapped"
    elif in_networks(address, DOCUMENTATION_NETWORKS):
        scope = "documentation"
    elif address.is_unspecified:
        scope = "unspecified"
    elif address.is_loopback:
        scope = "loopback"
    elif address.is_link_local:
        scope = "link-local"
    elif address.is_multicast:
        scope = "multicast"
    elif in_networks(address, PRIVATE_NETWORKS):
        scope = "private"
    elif address.is_global:
        scope = "global-unicast"
    else:
        scope = "special-use"

    result = {
        "address": str(address),
        "version": address.version,
        "scope": scope,
        "assessment": "not-performed",
        "network_queries": 0,
    }
    if scope == "ipv4-mapped":
        result["embedded_ipv4"] = classify(str(address.ipv4_mapped))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", help="One IP address. Use documentation addresses for demos.")
    args = parser.parse_args(argv)
    try:
        result = classify(args.address)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
