from concurrent.futures import ThreadPoolExecutor
import socket

from core.logger import Logger


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

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((host, port))

            if result == 0:
                return port

            return None

        except (OSError, socket.timeout):
            return None
        except Exception as e:
            Logger.warning(f"Port scan error for {host}:{port} -> {e}")
            return None
        finally:
            sock.close()


    def scan_ports(self, host, ports):

        open_ports = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:

            results = executor.map(
                lambda p: self.scan_port(host, p),
                ports
            )

            for result in results:
                if result is not None:
                    open_ports.append(result)

        return sorted(open_ports)



