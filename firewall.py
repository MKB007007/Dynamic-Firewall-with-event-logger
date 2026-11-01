# Firewall switch (data plane).
# Holds a flow table and asks the controller on a table miss.

import socket
import json
import threading

from common import (
    FIREWALL_HOST,
    FIREWALL_PORT,
    CONTROLLER_HOST,
    CONTROLLER_PORT,
    SERVER_HOST,
    send_log,
)

flow_table = {}  # (src, dport) or (src, "*") -> "allow" | "deny" | "block"


def lookup(src, dport):
    # A block rule on the source beats everything else.
    return flow_table.get((src, "*")) or flow_table.get((src, dport))


def ask_controller(src, dport):
    try:
        with socket.create_connection(
            (CONTROLLER_HOST, CONTROLLER_PORT), timeout=3
        ) as s:
            s.sendall(json.dumps({"src": src, "dport": dport}).encode())
            rule = json.loads(s.recv(1024).decode())

    except (OSError, ValueError):
        # Controller unreachable: fail closed, install nothing.
        return "deny"

    # Install the rule returned by the controller.
    flow_table[tuple(rule["match"])] = rule["action"]

    print("Flow table:", flow_table)

    return rule["action"]


def handle(conn):
    # Application traffic format: source|destination_port|message
    try:
        src, dport, msg = conn.recv(1024).decode().split("|", 2)
        dport = int(dport)

    except ValueError:
        conn.sendall(b"BAD REQUEST")
        conn.close()
        return

    action = lookup(src, dport)
    how = "cached rule"

    if action is None:
        action = ask_controller(src, dport)
        how = "new rule from controller"

    send_log(
        "FIREWALL",
        action.upper(),
        f"{src} -> port {dport} ({how})",
    )

    if action == "allow":
        try:
            with socket.create_connection(
                (SERVER_HOST, dport), timeout=3
            ) as app:
                app.sendall(msg.encode())
                app.shutdown(socket.SHUT_WR)

                conn.sendall(app.recv(1024))

        except OSError:
            conn.sendall(b"SERVER DOWN")

    elif action == "deny":
        conn.sendall(b"DENIED by firewall")

    else:
        conn.sendall(b"BLOCKED by firewall")

    conn.close()


server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((FIREWALL_HOST, FIREWALL_PORT))
server.listen()

print(f"Firewall listening on {FIREWALL_PORT}...")

while True:
    conn, _ = server.accept()

    threading.Thread(
        target=handle,
        args=(conn,),
        daemon=True,
    ).start()