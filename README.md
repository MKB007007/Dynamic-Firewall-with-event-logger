# Dynamic-Firewall-with-event-logger
SDN Dynamic Firewall with Security Event Logger
Architecture
 client.py --> firewall.py (data plane, flow table) --> app_server.py (:9000)
                  |  table miss? "packet-in"
                  v
             controller.py (control plane, policy)  --"flow-mod" rule-->  back to firewall
                  |                    |
                  +---- security events (sockets) ----> logger_server.py --> security_events.log
SDN idea: control plane (controller) is separate from data plane (firewall). The firewall only forwards; the controller decides and installs rules dynamically.

Files
common.py (ports + log helper), logger_server.py, controller.py, firewall.py, app_server.py, client.py, attacker.py, test_all.py (26 automated tests), README.md

Policy (controller.py)
ALLOW: destination port 9000 (the app)
DENY: any other port (default deny)
BLOCK: a source denied on 3 different ports (port scan) is blocked on ALL ports
Controller unreachable: new flows are denied (fail closed)
Run (4 terminals, in this folder, in this order)
python logger_server.py
python controller.py
python app_server.py
python firewall.py
A 5th terminal is the demo terminal (client).

Demo script
Allowed (new rule installed by controller): python client.py alice 9000 hello
Same again, served from the cached rule: python client.py alice 9000 hello again
Forbidden port, denied: python client.py bob 23 hi
Port scan, denied twice, then auto-blocked, then even port 9000 is blocked: python attacker.py
Alice is unaffected: python client.py alice 9000 still ok
Show the logger terminal and security_events.log with every event.
