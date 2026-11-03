from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import time

ALLOWED_PORTS = {9000}
SCAN_LIMIT = 3
SERVER_IP = "10.0.0.3"
LOGFILE = LOGFILE = "/home/kushal/Dynamic-Firewall-with-event-logger/demo/security_events.log"

denied_ports = {}   # src ip -> set of denied ports
blocked = set()     # src ips blocked entirely
mac_to_port = {}    # simple L2 learning


def log_event(source, level, msg):
    line = f"{time.strftime('%H:%M:%S')} [{source}] {level}: {msg}\n"
    print(line, end="")
    with open(LOGFILE, "a") as f:
        f.write(line)


def decide(src, dport):
    if src in blocked:
        return "block"
    if dport in ALLOWED_PORTS:
        return "allow"
    tried = denied_ports.setdefault(src, set())
    tried.add(dport)
    if len(tried) >= SCAN_LIMIT:
        blocked.add(src)
        log_event("CONTROLLER", "ALERT",
                  f"Port scan by '{src}' {sorted(tried)} -> BLOCK all traffic")
        return "block"
    return "deny"


def drop_rule(event, priority, hard_timeout=0, **match):
    fm = of.ofp_flow_mod()
    fm.match = of.ofp_match(**match)
    fm.priority = priority
    fm.hard_timeout = hard_timeout      # no actions == DROP
    event.connection.send(fm)


def forward(event, install):
    pkt = event.parsed
    out = mac_to_port.get(pkt.dst)
    if out is None:                      # unknown dst (e.g. ARP) -> flood
        po = of.ofp_packet_out(data=event.ofp)
        po.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(po)
        return
    if install:
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(pkt, event.port)
        fm.idle_timeout = 30
        fm.priority = 100
        fm.actions.append(of.ofp_action_output(port=out))
        fm.data = event.ofp
        event.connection.send(fm)
    else:
        po = of.ofp_packet_out(data=event.ofp)
        po.actions.append(of.ofp_action_output(port=out))
        event.connection.send(po)


def _handle_PacketIn(event):
    pkt = event.parsed
    if not pkt.parsed:
        return
    mac_to_port[pkt.src] = event.port
    ip, tcp = pkt.find("ipv4"), pkt.find("tcp")

    # Firewall policy applies to TCP going toward the server; replies pass.
    if ip and tcp and str(ip.srcip) != SERVER_IP:
        src, dport = str(ip.srcip), tcp.dstport
        action = decide(src, dport)
        log_event("FIREWALL", action.upper(), f"{src} -> port {dport}")
        if action == "allow":
            forward(event, install=True)
        elif action == "deny":
            drop_rule(event, 200, hard_timeout=30,
                      dl_type=0x0800, nw_proto=6,
                      nw_src=IPAddr(src), tp_dst=dport)
        else:  # block everything from this source
            drop_rule(event, 300, dl_type=0x0800, nw_src=IPAddr(src))
        return

    forward(event, install=bool(ip and tcp))


def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log_event("CONTROLLER", "INFO", "SDN firewall controller started")
