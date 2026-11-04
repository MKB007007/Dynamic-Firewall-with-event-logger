#!/usr/bin/env python3
"""Dynamic (POX) vs static (fixed ACL) firewall evaluation.
Usage:  sudo python3 evaluation/evaluate.py dynamic   (POX controller must be running)
        sudo python3 evaluation/evaluate.py static    (no controller)
"""
import csv, json, math, os, re, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "topology"))

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel
from topo import FirewallTopo

SERVER = "10.0.0.3"
REPEATS = 3
LEVELS = [1, 10, 50, 100]
REQUESTS = 1000
OUT = os.path.join(HERE, "results")

STATIC_RULES = [
    "priority=200,tcp,tp_dst=9000,actions=normal",   # traffic to the app server
    "priority=200,tcp,tp_src=9000,actions=normal",   # server replies
    "priority=100,tcp,actions=drop",                 # every other TCP port
    "priority=50,actions=normal",                    # ARP, ICMP, ...
]
ATTACK = "while true; do for p in $(seq 1 150); do nc -z -w1 10.0.0.3 $p & done; sleep 1; done"

mode = sys.argv[1] if len(sys.argv) > 1 else ""
if mode not in ("dynamic", "static"):
    sys.exit("usage: sudo python3 evaluation/evaluate.py dynamic|static")

rows = []


def record(cond, metric, run, value):
    rows.append([mode, cond, metric, run, value])
    print("  %-18s %-18s %s" % (cond, metric, value))


def reset_flows(s1):
    if mode == "dynamic":              # static mode must keep its fixed rules
        s1.cmd("ovs-ofctl del-flows s1")
        time.sleep(0.3)


def flow_count(s1):
    out = s1.cmd("ovs-ofctl dump-flows s1 | grep -c cookie=").strip()
    return int(out) if out.isdigit() else -1


def start_http(h3):
    h3.cmd("pkill -f http.server")
    h3.cmd("mkdir -p /tmp/www && echo ok > /tmp/www/index.html")
    h3.cmd("cd /tmp/www && python3 %s >/dev/null 2>&1 &" % os.path.join(HERE, "http_server.py"))
    time.sleep(1)


def run_iperf(h1, h3, streams):
    h3.cmd("pkill -f http.server; pkill iperf3; iperf3 -s -p 9000 -D")
    time.sleep(1)
    out = h1.cmd("iperf3 -c %s -p 9000 -t 10 -P %d -J" % (SERVER, streams))
    h3.cmd("pkill iperf3")
    start_http(h3)
    try:
        return json.loads(out)["end"]["sum_received"]["bits_per_second"] / 1e6
    except (ValueError, KeyError):
        return math.nan


def run_ab(h1, n, c):
    out = h1.cmd("ab -r -q -n %d -c %d http://%s:9000/ 2>&1" % (n, c, SERVER))
    try:
        rps = float(re.search(r"Requests per second:\s+([\d.]+)", out).group(1))
        ms = float(re.search(r"Time per request:\s+([\d.]+) \[ms\] \(mean\)", out).group(1))
        failed = int(re.search(r"Failed requests:\s+(\d+)", out).group(1))
        return rps, ms, failed
    except AttributeError:
        return math.nan, math.nan, n


def curl_connect_ms(h1):
    out = h1.cmd("curl -s -o /dev/null -m 5 -w '%%{time_connect}' %s:9000" % SERVER).strip()
    try:
        return float(out) * 1000
    except ValueError:
        return math.nan


def http_ok(host):
    code = host.cmd("curl -s -o /dev/null -m 3 -w '%%{http_code}' %s:9000" % SERVER).strip()
    return int(code == "200")


def main():
    setLogLevel("warning")
    controller = None
    if mode == "dynamic":
        controller = lambda n: RemoteController(n, ip="127.0.0.1", port=6633)
    net = Mininet(topo=FirewallTopo(), controller=controller,
                  switch=lambda n, **kw: OVSSwitch(n, protocols="OpenFlow10", **kw))
    net.start()
    try:
        s1, h1, h2, h3 = net.get("s1", "h1", "h2", "h3")
        if mode == "dynamic":
            time.sleep(3)                       # let the switch connect to POX
        else:
            for rule in STATIC_RULES:
                s1.cmd('ovs-ofctl add-flow s1 "%s"' % rule)
        net.pingAll()
        start_http(h3)

        # ---- Phase A: normal conditions, repeated ----
        for run in range(1, REPEATS + 1):
            print("\n=== run %d/%d ===" % (run, REPEATS))
            reset_flows(s1)
            record("latency", "connect_cold_ms", run, round(curl_connect_ms(h1), 2))
            record("latency", "connect_warm_ms", run, round(curl_connect_ms(h1), 2))

            for streams in (1, 4):
                reset_flows(s1)
                record("throughput", "mbps_%dstream" % streams, run,
                       round(run_iperf(h1, h3, streams), 1))

            for c in LEVELS:
                reset_flows(s1)
                rps, ms, failed = run_ab(h1, REQUESTS, c)
                cond = "concurrency_%d" % c
                record(cond, "req_per_sec", run, rps)
                record(cond, "ms_per_request", run, ms)
                record(cond, "failed", run, failed)
                record(cond, "flow_entries", run, flow_count(s1))

        # ---- Phase B: alice's load while the attacker scans (single run) ----
        print("\n=== attack condition ===")
        reset_flows(s1)
        attack = h2.popen(["bash", "-c", ATTACK])
        time.sleep(0.5)
        rps, ms, failed = run_ab(h1, 3000, 50)
        attack.kill()
        h2.cmd("pkill -x nc")
        record("attack", "req_per_sec", 1, rps)
        record("attack", "ms_per_request", 1, ms)
        record("attack", "failed", 1, failed)
        record("attack", "flow_entries", 1, flow_count(s1))

        # ---- Security outcome: can the scanner still reach the app? ----
        time.sleep(2)
        reset_flows(s1)
        record("security", "attacker_reached_server", 1, http_ok(h2))
        record("security", "alice_reached_server", 1, http_ok(h1))

        os.makedirs(OUT, exist_ok=True)
        path = os.path.join(OUT, "results_%s.csv" % mode)
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["mode", "condition", "metric", "run", "value"])
            w.writerows(rows)
        print("\nSaved", path)
    finally:
        net.stop()


main()
