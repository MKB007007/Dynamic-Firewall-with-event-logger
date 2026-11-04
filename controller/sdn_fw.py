"""POX OpenFlow 1.0 dynamic firewall with a separate TCP logging server.

Run the logger_server.py process first, then start POX with this module:
    python3 -u ./pox.py log.level --INFO openflow.of_01 sdn_fw

By default the logger is expected on 127.0.0.1:7000. If it runs on another
machine, set LOGGER_HOST to that machine's reachable IP address.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import os
import socket
import time
from datetime import datetime
packet_in_count = 0

ALLOWED_PORTS = {9000}
SCAN_LIMIT = 3
SERVER_IP = "10.0.0.3"

LOGGER_HOST = os.environ.get("LOGGER_HOST", "127.0.0.1")
LOGGER_PORT = int(os.environ.get("LOGGER_PORT", "7000"))
LOGGER_TIMEOUT = float(os.environ.get("LOGGER_TIMEOUT", "1.0"))

# src IP -> set of distinct unauthorized destination ports
# These are in-memory controller state.
denied_ports = {}
blocked = set()
mac_to_port = {}


def log_event(source, level, msg):
    """Print an event locally and forward it to the separate TCP logger."""
    # Benchmark mode: skip high-volume ALLOW events so logging doesn't skew results.
    if os.environ.get("FW_BENCH") and level == "ALLOW":
        return

    line = "{} [{}] {}: {}\n".format(
        datetime.now().strftime("%H:%M:%S.%f")[:-3], source, level, msg   # millisecond timestamps
    )
    print(line, end="")

    try:
        with socket.create_connection(
            (LOGGER_HOST, LOGGER_PORT), timeout=LOGGER_TIMEOUT
        ) as logger_socket:
            logger_socket.sendall(line.encode("utf-8"))
    except OSError as exc:
        # Logging failure must not crash the controller or stop packet handling.
        print("[LOGGER-ERROR] Could not send event to {}:{}: {}".format(
            LOGGER_HOST, LOGGER_PORT, exc
        ))


def decide(src, dport):
    if src in blocked:
        return "block"

    if dport in ALLOWED_PORTS:
        return "allow"

    tried = denied_ports.setdefault(src, set())
    tried.add(dport)

    if len(tried) >= SCAN_LIMIT:
        blocked.add(src)
        log_event(
            "CONTROLLER",
            "ALERT",
            "Port scan by '{}' {} -> BLOCK all traffic".format(src, sorted(tried)),
        )
        return "block"

    return "deny"


def drop_rule(event, priority, hard_timeout=0, **match):
    """Install a drop rule; an OpenFlow flow with no output action drops."""
    flow_mod = of.ofp_flow_mod()
    flow_mod.match = of.ofp_match(**match)
    flow_mod.priority = priority
    flow_mod.hard_timeout = hard_timeout
    event.connection.send(flow_mod)


def forward(event, install):
    """Forward a packet and optionally install a matching forwarding rule."""
    packet = event.parsed
    output_port = mac_to_port.get(packet.dst)

    if output_port is None:  # Unknown destination (for example, ARP): flood.
        packet_out = of.ofp_packet_out(data=event.ofp)
        packet_out.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(packet_out)
        return

    if install:
        flow_mod = of.ofp_flow_mod()
        ip_packet = packet.find("ipv4")
        tcp_segment = packet.find("tcp")
        match = dict(dl_type=0x0800, nw_proto=6,
                     nw_src=ip_packet.srcip, nw_dst=ip_packet.dstip)
        if str(ip_packet.dstip) == SERVER_IP:
            match["tp_dst"] = tcp_segment.dstport     # client -> server: any source port
        else:
            match["tp_src"] = tcp_segment.srcport     # server -> client: any client port
        flow_mod.match = of.ofp_match(**match)
        flow_mod.idle_timeout = 30
        flow_mod.priority = 100
        flow_mod.actions.append(of.ofp_action_output(port=output_port))
        flow_mod.data = event.ofp
        event.connection.send(flow_mod)
    else:
        packet_out = of.ofp_packet_out(data=event.ofp)
        packet_out.actions.append(of.ofp_action_output(port=output_port))
        event.connection.send(packet_out)


def _handle_PacketIn(event):
    packet = event.parsed
    if not packet.parsed:
        return

    mac_to_port[packet.src] = event.port
    ip_packet = packet.find("ipv4")
    tcp_segment = packet.find("tcp")

    # Apply the firewall policy only to TCP traffic destined for the protected
    # application server. Return traffic from the server is forwarded normally.
    if ip_packet and tcp_segment and str(ip_packet.dstip) == SERVER_IP:
        source_ip = str(ip_packet.srcip)
        destination_port = tcp_segment.dstport

        action = decide(source_ip, destination_port)
        log_event(
            "FIREWALL",
            action.upper(),
            "{} -> {}:{}".format(source_ip, SERVER_IP, destination_port),
        )

        if action == "allow":
            forward(event, install=True)
        elif action == "deny":
            # Deny only this source -> protected server destination-port flow.
            drop_rule(
                event,
                200,
                hard_timeout=30,
                dl_type=0x0800,
                nw_proto=6,
                nw_src=IPAddr(source_ip),
                nw_dst=IPAddr(SERVER_IP),
                tp_dst=destination_port,
            )
        else:  # BLOCK all IPv4 traffic from this source IP.
            drop_rule(
                event,
                300,
                dl_type=0x0800,
                nw_src=IPAddr(source_ip),
            )
        return

    # Forward server replies and non-protected traffic.
    forward(event, install=bool(ip_packet and tcp_segment))


def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log_event("CONTROLLER", "INFO", "SDN firewall controller started")
