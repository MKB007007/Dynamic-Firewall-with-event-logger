#!/bin/bash
# Run from repo root:  ./demo/1_start_controller.sh
cd "$(dirname "$0")/.."
ln -sf "$PWD/controller/sdn_fw.py" ~/pox/ext/sdn_fw.py   # repo file is the source of truth
rm -f demo/security_events.log
python3 ~/pox/pox.py log.level --INFO openflow.of_01 sdn_fw
