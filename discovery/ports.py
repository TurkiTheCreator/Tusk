from concurrent.futures import ThreadPoolExecutor
import socket

from core.logger import Logger
from core.utils import get_all_addresses


# The 100 most common TCP ports, ordered by frequency (Nmap top-100 list).
TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
    5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
    2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
    544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
    6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
]


class PortScanner:

    def __init__(self, threads=100, timeout=1):
        self.threads = threads
        self.timeout = timeout

    def _validate_port(self, port):
        if not isinstance(port, int):
            raise ValueError(f"Invalid port (not an int): {port}")
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")

    def scan_port(self, host, port):
        self._validate_port(port)

        addresses = get_all_addresses(host, port)
        if not addresses:
            Logger.warning(f"Could not resolve {host}:{port}")
            return None

        for family, socktype, proto, canonname, address in addresses:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(self.timeout)

            try:
                result = sock.connect_ex(address)
                if result == 0:
                    sock.close()
                    return port
            except (OSError, socket.timeout):
                pass
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        return None

    def scan_ports(self, host, ports):
        open_ports = []

        # Avoid lambda overhead: bind host once.
        def _scan(p):
            return self.scan_port(host, p)

        ports = list(ports)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(_scan, ports)
            for result in results:
                if result is not None:
                    open_ports.append(result)

        return sorted(open_ports)




