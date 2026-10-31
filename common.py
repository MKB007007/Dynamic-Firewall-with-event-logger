import socket
import time

HOST = "127.0.0.1"
LOGGER_PORT = 7000       # central security log server
CONTROLLER_PORT = 6000   # SDN controller (control plane)
FIREWALL_PORT = 8000     # firewall switch (data plane)
SERVER_PORT = 9000       # the protected application server


def send_log(source, level, message):
    """Send one security event to the central logging server over a socket."""
    line = f"{time.strftime('%H:%M:%S')} [{source}] {level}: {message}\n"
    try:
        with socket.create_connection((HOST, LOGGER_PORT), timeout=2) as s:
            s.sendall(line.encode())
    except OSError:
        print("(logger unreachable)", line.strip())
