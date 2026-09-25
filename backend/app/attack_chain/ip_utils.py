import ipaddress

def canonical_ip(raw: str) -> str:
    """
    Strict standard library IP parsing.
    Raises ValueError if raw is not a valid IP address.
    IPv4 -> dotted-decimal ('192.168.1.1')
    IPv6 -> compressed form ('2001:db8::1') per RFC 5952
    
    CRITICAL (Correction C8): Leading-zero IPv4 representations
    (e.g., '192.168.001.001') raise ValueError under strict stdlib
    behavior and MUST NOT be rewritten or normalized.
    """
    return str(ipaddress.ip_address(raw.strip()))
