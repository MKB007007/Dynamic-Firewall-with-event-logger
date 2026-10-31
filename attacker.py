# Simulates a port scan, then tries the legit port to show the block is total.
import subprocess
import sys

for port in [22, 23, 3306, 9000]:
    subprocess.run([sys.executable, "client.py", "attacker", str(port), "probe"])
