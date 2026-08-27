import socket
from typing import Optional, Tuple, List


def resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to IP address (first result)."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def get_all_addresses(host: str, port: int) -> List[Tuple]:
    """Get all resolved addresses for a host and port, supporting IPv4 and IPv6.
    
    Returns a list of tuples (family, socktype, proto, canonname, address_tuple).
    Addresses are deduplicated to avoid redundant connection attempts.
    """
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        seen = set()
        unique = []
        for family, socktype, proto, canonname, address in addresses:
            addr_key = (family, address)
            if addr_key not in seen:
                seen.add(addr_key)
                unique.append((family, socktype, proto, canonname, address))
        return unique
    except socket.gaierror:
        return []