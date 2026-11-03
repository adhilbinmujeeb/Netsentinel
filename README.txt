NetSentinel - Network Attack Detection and Security Auditing Tool

INSTALL (Fedora)
  sudo dnf install python3-scapy python3-reportlab python3-matplotlib tcpdump nmap wireshark-cli
  (or: pip install scapy reportlab matplotlib)

RUN ON A PCAP
  python3 netsentinel.py capture.pcap
  python3 netsentinel.py capture.pcap --csv out.csv --json out.json --pdf out.pdf
  python3 netsentinel.py capture.pcap --config thresholds.json --whitelist 192.168.1.1

LIVE (root needed; use only on your own machine or an isolated lab)
  sudo python3 netsentinel.py --live eth0 --duration 60 --pdf live_report.pdf

REAL-TRAFFIC TEST ON YOUR OWN MACHINE
  sudo tcpdump -i lo -w real_scan.pcap &
  nmap -sS -p 1-1000 127.0.0.1
  sudo pkill tcpdump
  python3 netsentinel.py real_scan.pcap --pdf real_scan_report.pdf

REPRODUCE THE EVALUATION
  python3 generate_traffic.py      (writes 120 labelled PCAPs to lab_pcaps/, sends nothing)
  python3 run_experiments.py       (metrics -> results.json, charts -> chart_*.png)
  python3 -m unittest -v test_netsentinel

THRESHOLDS (edit via --config JSON; only keys you give are overridden)
  {"port_scan": {"threshold": 15, "window": 10},
   "syn_burst": {"threshold": 100, "window": 5},
   "repeat_conn": {"threshold": 20, "window": 30}}
