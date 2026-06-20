
import socket


class BannerGrabber:

    def __init__(self, timeout=2):
        self.timeout = timeout


    def grab_banner(self, host, port):

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(self.timeout)

            sock.connect((host, port))

            if port in [80, 443]:

                request = (
                    "HEAD / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Connection: close\r\n\r\n"
                )

                sock.send(request.encode())

            banner = sock.recv(1024)

            sock.close()

            return banner.decode(
                errors="ignore"
            ).strip()

        except Exception:
            return ""


    def grab_banners(self, host, ports):

        banners = {}

        for port in ports:

            banners[port] = self.grab_banner(
                host,
                port
            )

        return banners

