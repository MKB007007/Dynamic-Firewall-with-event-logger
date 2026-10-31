# Usage: python client.py <name> <destination_port> <message>
# Sends one application message through the firewall.
import socket
import sys
from common import HOST, FIREWALL_PORT

name, port, message = sys.argv[1], sys.argv[2], " ".join(sys.argv[3:]) or "hello"

with socket.create_connection((HOST, FIREWALL_PORT)) as s:
    s.sendall(f"{name}|{port}|{message}".encode())
    print(f"[{name} -> port {port}]", s.recv(1024).decode())
  
