import socket
import time

# Mininet host addresses
HOST = "127.0.0.1"

LOGGER_HOST = "10.0.0.2"
CONTROLLER_HOST = "10.0.0.2"
FIREWALL_HOST = "10.0.0.2"
SERVER_HOST = "127.0.0.1"

LOGGER_PORT = 7000
CONTROLLER_PORT = 6000
FIREWALL_PORT = 8000
SERVER_PORT = 9000


def send_log(source, level, message):
    """Send one security event to the central logging server over a socket."""
    line = f"{time.strftime('%H:%M:%S')} [{source}] {level}: {message}\n"

    try:
        with socket.create_connection((LOGGER_HOST, LOGGER_PORT), timeout=2) as s:
            s.sendall(line.encode())
    except OSError:
        print("(logger unreachable)", line.strip())