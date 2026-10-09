import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

from core.logger import Logger
from core.utils import get_all_addresses


class BannerGrabber:
    """Protocol-aware banner grabbing.

    Public API preserved:
      - __init__(timeout=...)
      - grab_banners(host, ports) -> dict[port, banner_str]

    Returns an empty string on failures to preserve existing scan behavior.
    """

    def __init__(self, timeout=2, max_workers=50):
        self.timeout = timeout
        self.max_workers = max_workers

    def _create_connection(self, host: str, port: int) -> socket.socket:
        """Create a dual-stack socket connection (IPv4 or IPv6).
        
        Returns the connected socket, or raises an exception if all attempts fail.
        """
        addresses = get_all_addresses(host, port)
        if not addresses:
            raise OSError(f"Could not resolve {host}:{port}")

        last_error = None
        for family, socktype, proto, canonname, address in addresses:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(self.timeout)

            try:
                sock.connect(address)
                return sock
            except (OSError, socket.timeout) as e:
                last_error = e
                try:
                    sock.close()
                except Exception:
                    pass

        if last_error:
            raise last_error
        raise OSError(f"Failed to connect to {host}:{port}")

    def _safe_recv(self, sock: socket.socket, nbytes: int, context: str = "") -> bytes:
        try:
            data = sock.recv(nbytes)
            return data
        except socket.timeout:
            return b""
        except Exception:
            return b""



    def _read_until_close(self, sock: socket.socket, max_bytes: int, context: str = "") -> bytes:
        """Bounded read loop to collect initial protocol banner/headers."""
        data = bytearray()
        while len(data) < max_bytes:
            chunk = self._safe_recv(sock, min(4096, max_bytes - len(data)), context=context)
            if not chunk:
                break
            data.extend(chunk)
            if len(chunk) < 4096:
                break
        return bytes(data)


    def _probe_http(self, host: str, port: int) -> str:
        sock = None
        try:
            sock = self._create_connection(host, port)

            request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n"
                "User-Agent: TuskBannerGrabber/1.0\r\n\r\n"
            )
            sock.sendall(request.encode(errors="ignore"))

            resp = self._read_until_close(sock, max_bytes=8192)
            return resp.decode(errors="ignore").strip()
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _probe_https(self, host: str, port: int) -> str:
        sock = None
        tls_sock = None
        try:
            sock = self._create_connection(host, port)

            context = ssl.create_default_context()
            # Security tradeoff: fingerprinting should not fail due to cert errors.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            tls_sock = context.wrap_socket(sock, server_hostname=host)

            request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n"
                "User-Agent: TuskBannerGrabber/1.0\r\n\r\n"
            )
            tls_sock.sendall(request.encode(errors="ignore"))

            resp = self._read_until_close(tls_sock, max_bytes=8192)
            return resp.decode(errors="ignore").strip()
        finally:
            for s in (tls_sock, sock):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _probe_ssh(self, host: str, port: int) -> str:
        sock = self._create_connection(host, port)
        try:

            # SSH server banner is typically sent immediately.
            # Read just the first banner bytes (bounded). Some SSH servers may
            # not send a banner immediately when unauthenticated; keep it best-effort.
            data = self._safe_recv(sock, 1024, context=f"ssh:{host}:{port} greeting")
            return data.decode(errors="ignore").strip()

        finally:
            try:
                sock.close()
            except Exception:
                pass


    def _probe_ftp(self, host: str, port: int) -> str:
        sock = self._create_connection(host, port)
        try:

            banner = self._read_until_close(sock, max_bytes=2048)

            # Optionally elicit more info (best-effort).
            try:
                sock.sendall(b"FEAT\r\n")
                extra = self._read_until_close(sock, max_bytes=2048)
                banner = banner + extra
            except Exception:
                pass

            return banner.decode(errors="ignore").strip()
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _probe_smtp(self, host: str, port: int) -> str:
        sock = self._create_connection(host, port)
        try:

            banner = self._read_until_close(sock, max_bytes=2048)

            # Best-effort: EHLO to improve fingerprinting.
            try:
                sock.sendall(b"EHLO tusk.local\r\n")
                extra = self._read_until_close(sock, max_bytes=4096)
                banner = banner + extra
            except Exception:
                pass

            return banner.decode(errors="ignore").strip()
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _probe_smtps_implicit_tls(self, host: str, port: int) -> str:
        sock = self._create_connection(host, port)
        tls_sock = None
        try:

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            tls_sock = context.wrap_socket(sock, server_hostname=host)

            banner = self._read_until_close(tls_sock, max_bytes=2048)

            try:
                tls_sock.sendall(b"EHLO tusk.local\r\n")
                extra = self._read_until_close(tls_sock, max_bytes=4096)
                banner = banner + extra
            except Exception:
                pass

            return banner.decode(errors="ignore").strip()
        finally:
            for s in (tls_sock, sock):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _probe_passive(self, host: str, port: int) -> str:
        """Connect and just listen: SSH/FTP/SMTP/etc. speak first."""
        sock = None
        try:
            sock = self._create_connection(host, port)
            return self._read_until_close(sock, max_bytes=2048).decode(errors="ignore").strip()
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _try(self, probe, host: str, port: int) -> str:
        try:
            return probe(host, port)
        except Exception as e:
            # Closed/quiet ports are normal; only show with --verbose.
            Logger.debug(f"{probe.__name__} {host}:{port} -> {e}")
            return ""

    def grab_banner(self, host, port):
        """Grab a banner by behavior: passive read, then HTTP, then TLS. Never raises."""
        # Probes that must send something to get a full banner.
        if port == 465:
            return self._try(self._probe_smtps_implicit_tls, host, port)
        if port in (25, 587):
            return self._try(self._probe_smtp, host, port)
        if port == 21:
            return self._try(self._probe_ftp, host, port)

        banner = self._try(self._probe_passive, host, port)
        if banner:
            return banner

        banner = self._try(self._probe_http, host, port)
        if banner.startswith("HTTP/"):
            return banner

        return self._try(self._probe_https, host, port)

    def grab_banners(self, host, ports):
        banners = {}
        ports = list(ports)

        def _grab(p):
            return p, self.grab_banner(host, p)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for port, banner in executor.map(_grab, ports):
                banners[port] = banner

        return banners

