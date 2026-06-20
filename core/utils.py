import socket


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None