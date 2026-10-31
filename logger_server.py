# Centralized security event logging server.
import socket
from common import HOST, LOGGER_PORT

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, LOGGER_PORT))
server.listen()
print(f"Logger server listening on {LOGGER_PORT}...")

while True:
    conn, _ = server.accept()
    event = conn.recv(1024).decode()
    conn.close()
    print(event, end="")                      # show live on screen
    with open("security_events.log", "a") as f:
        f.write(event)                        # keep a permanent record
