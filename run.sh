#!/bin/bash

python collapse.py
python plot_tcpprobe.py -f cwnd.txt -o cwnd-iperf.png -p 5001
