# SDN controller: the "brain". Decides allow / deny / block for new flows.
import socket
import json
from common import HOST, CONTROLLER_PORT, SERVER_PORT, send_log

ALLOWED_PORTS = {SERVER_PORT}   # policy: only the app server port is allowed
SCAN_LIMIT = 3                  # 3 different denied ports => port scan => block
denied_ports = {}               # source -> set of ports it tried and was denied


def decide(src, dport):
    if dport in ALLOWED_PORTS:
        return {"action": "allow", "match": [src, dport]}

    tried = denied_ports.setdefault(src, set())
    tried.add(dport)
    if len(tried) >= SCAN_LIMIT:
        send_log("CONTROLLER", "ALERT", f"Port scan by '{src}' {sorted(tried)} -> BLOCK all traffic")
        return {"action": "block", "match": [src, "*"]}
    return {"action": "deny", "match": [src, dport]}


server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, CONTROLLER_PORT))
server.listen()
print(f"Controller listening on {CONTROLLER_PORT}...")

while True:
    conn, _ = server.accept()
    request = json.loads(conn.recv(1024).decode())          # "packet-in" from switch
    rule = decide(request["src"], request["dport"])
    print(f"packet-in {request} -> {rule['action'].upper()}")
    conn.sendall(json.dumps(rule).encode())                  # "flow-mod" back to switch
    conn.close()
