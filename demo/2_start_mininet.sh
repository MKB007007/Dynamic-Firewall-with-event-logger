#!/bin/bash
# Run from repo root:  ./demo/2_start_mininet.sh
cd "$(dirname "$0")/.."
sudo mn -c
sudo python3 topology/topo.py
