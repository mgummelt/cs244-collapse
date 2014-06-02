#!/bin/bash

python collapse.py
python plot_tcpprobe.py -f out/cwnd.txt -o out/cwnd.png --sport -p 8000
python plot_tcpprobe.py -f out/cwnd_lazy.txt -o out/cwnd_lazy.png --sport -p 8000
