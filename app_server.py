# The protected application server (simple echo service).
import socket
from common import HOST, SERVER_PORT

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, SERVER_PORT))
server.listen()
print(f"App server listening on {SERVER_PORT}...")

while True:
    conn, _ = server.accept()
    msg = conn.recv(1024).decode()
    conn.sendall(f"SERVER replied: got '{msg}'".encode())
    conn.close()
