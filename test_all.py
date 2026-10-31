# Automated tests. Run: python test_all.py   (starts and stops all components itself)
import os
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from common import HOST, FIREWALL_PORT

procs = {}
passed = failed = 0


def start(name):
    procs[name] = subprocess.Popen([sys.executable, name + ".py"], stdout=subprocess.DEVNULL)
    time.sleep(0.6)


def stop(name):
    procs.pop(name).kill()
    time.sleep(0.3)


def send(raw, timeout=5):
    """Send raw bytes to the firewall, return the reply text ('' if none)."""
    try:
        with socket.create_connection((HOST, FIREWALL_PORT), timeout=timeout) as s:
            s.sendall(raw.encode())
            return s.recv(1024).decode()
    except OSError as e:
        return f"<error {e}>"


def check(name, got, want):
    global passed, failed
    ok = want in got
    passed += ok
    failed += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"   got={got!r} want~{want!r}"))


if os.path.exists("security_events.log"):
    os.remove("security_events.log")
for p in ["logger_server", "controller", "app_server", "firewall"]:
    start(p)

try:
    print("--- basic policy ---")
    check("allow app port", send("alice|9000|hi"), "got 'hi'")
    check("cached allow", send("alice|9000|hi2"), "got 'hi2'")
    check("deny other port", send("bob|23|x"), "DENIED")
    check("deny cached", send("bob|23|x"), "DENIED")
    check("deny controller port (6000)", send("bob|6000|x"), "DENIED")
    check("message with | inside", send("alice|9000|a|b|c"), "got 'a|b|c'")

    print("--- port scan -> block ---")
    send("evil|21|x"); send("evil|22|x")
    check("3rd distinct port blocks", send("evil|23|x"), "BLOCKED")
    check("blocked on allowed port too", send("evil|9000|x"), "BLOCKED")
    check("other user unaffected", send("alice|9000|ok"), "got 'ok'")
    for _ in range(5):
        send("lazy|22|x")
    check("same port repeated is NOT a scan", send("lazy|9000|ok"), "got 'ok'")

    print("--- bad input ---")
    check("garbage (no pipes)", send("hello"), "BAD REQUEST")
    check("non-numeric port", send("a|abc|x"), "BAD REQUEST")
    check("huge port number", send("a|99999999|x"), "DENIED")
    check("empty message", send("zed|9000|"), "got ''")
    check("firewall still alive after bad input", send("alice|9000|alive"), "got 'alive'")

    print("--- concurrency: 60 parallel clients ---")
    with ThreadPoolExecutor(20) as pool:
        replies = list(pool.map(lambda i: send(f"user{i}|9000|m{i}"), range(60)))
    check("all 60 answered correctly", str(sum(f"got 'm{i}'" in r for i, r in enumerate(replies))), "60")

    print("--- failure handling ---")
    stop("app_server")
    check("app server down -> clean message", send("alice|9000|x"), "SERVER DOWN")
    start("app_server")
    check("app server back up", send("alice|9000|x"), "got 'x'")

    stop("logger_server")
    check("logger down: firewall still works", send("carol|9000|x"), "got 'x'")
    start("logger_server")

    stop("controller")
    check("controller down: new flow fails closed", send("newuser|9000|x"), "DENIED")
    check("controller down: cached flow still works", send("alice|9000|x"), "got 'x'")
    start("controller")
    check("controller back: new flow works", send("dave|9000|x"), "got 'x'")

    print("--- logger recorded events ---")
    time.sleep(0.5)
    log = open("security_events.log").read()
    check("log has ALLOW", log, "ALLOW")
    check("log has DENY", log, "DENY")
    check("log has BLOCK", log, "BLOCK")
    check("log has scan ALERT", log, "Port scan by 'evil'")
finally:
    for p in list(procs):
        procs.pop(p).kill()

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)


