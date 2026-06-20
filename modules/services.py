import socket


class ServiceDetector:

    def detect(self, port):

        try:
            return socket.getservbyport(port)

        except OSError:
            return "unknown"


    def detect_services(self, ports):

        services = {}

        for port in ports:
            services[port] = self.detect(port)

        return services