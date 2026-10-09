import socket
from functools import lru_cache
from typing import Optional, Tuple, List


@lru_cache(maxsize=256)
def _resolve_cached(host: str) -> Tuple[Tuple, ...]:
    """One DNS lookup per host per run (port 0 placeholder, filled in later)."""
    try:
        infos = socket.getaddrinfo(host, 0, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return ()
    seen = set()
    unique = []
    for family, socktype, proto, canonname, sockaddr in infos:
        key = (family, sockaddr[0])
        if key not in seen:
            seen.add(key)
            unique.append((family, socktype, proto, canonname, sockaddr))
    return tuple(unique)


def resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to an IP string (IPv4 or IPv6), or None."""
    addrs = _resolve_cached(host)
    return addrs[0][4][0] if addrs else None


def get_all_addresses(host: str, port: int) -> List[Tuple]:
    """Cached addresses with `port` filled in (works for IPv4 and IPv6 sockaddrs).

    Returns a list of tuples (family, socktype, proto, canonname, address_tuple).
    """
    return [
        (family, socktype, proto, canon, (sockaddr[0], port, *sockaddr[2:]))
        for family, socktype, proto, canon, sockaddr in _resolve_cached(host)
    ]
