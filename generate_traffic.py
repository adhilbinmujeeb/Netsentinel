#!/usr/bin/env python3
"""
Generate labelled synthetic PCAP files for evaluating NetSentinel.

IMPORTANT: this only WRITES packets to PCAP files. Nothing is sent on any network.
Real-world validation should additionally be done with Nmap in an isolated lab
(see README.txt).

Scenarios (N runs each, randomised with a fixed seed for reproducibility):
  normal      ordinary client/server traffic (complete handshakes, few connections)
  busy_benign benign but heavy client (e.g. API polling) - stress test for false positives
  portscan    fast SYN scan of many ports (Nmap -sS style)
  synburst    high-rate SYN flood towards one host (single and spoofed sources)
  bruteforce  repeated connection attempts to SSH (port 22)
  slowscan    low-and-slow scan designed to stay below thresholds (evasion test)
"""
import json
import os
import random
import sys

from scapy.all import Ether, IP, TCP, PcapWriter

OUT = "lab_pcaps"
RUNS = 20
SEED = 1337
SERVER_PORTS = [22, 25, 53, 80, 110, 143, 443, 3306, 8080]


def pkt(ts, src, dst, sport, dport, flags):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    p.time = ts
    return p


def handshake(ts, c, s, dport, rng):
    sport = rng.randint(1025, 65000)
    return [pkt(ts, c, s, sport, dport, "S"),
            pkt(ts + 0.001, s, c, dport, sport, "SA"),
            pkt(ts + 0.002, c, s, sport, dport, "A"),
            pkt(ts + 0.05, c, s, sport, dport, "PA"),
            pkt(ts + 0.10, s, c, dport, sport, "PA")]


def scen_normal(rng, t0):
    clients = [f"192.168.1.{i}" for i in rng.sample(range(10, 60), rng.randint(5, 10))]
    servers = ["192.168.1.1", "192.168.1.5", "192.168.1.200"]
    out = []
    for c in clients:
        for _ in range(rng.randint(3, 12)):
            out += handshake(t0 + rng.uniform(0, 60), c, rng.choice(servers),
                             rng.choice(SERVER_PORTS[:5] + [443, 443, 80]), rng)
    return out, None


def scen_busy_benign(rng, t0):
    out, _ = scen_normal(rng, t0)
    c, s = "192.168.1.77", "192.168.1.5"
    n = rng.randint(8, 14)  # below repeat threshold: a heavy but legitimate client
    for i in range(n):
        out += handshake(t0 + 5 + i * rng.uniform(0.5, 2.0), c, s, 443, rng)
    return out, None


def scen_portscan(rng, t0):
    out, _ = scen_normal(rng, t0)
    atk, tgt = "192.168.1.105", "192.168.1.5"
    nports = rng.choice([20, 50, 100, 500, 1000])
    rate = rng.choice([50, 200, 1000])  # packets per second
    ports = rng.sample(range(1, 65536), nports)
    start = t0 + 10
    for i, p in enumerate(ports):
        ts = start + i / rate
        out.append(pkt(ts, atk, tgt, 40000 + i % 20000, p, "S"))
        if p in SERVER_PORTS:
            out.append(pkt(ts + 0.001, tgt, atk, p, 40000 + i % 20000, "SA"))
    return out, start


def scen_synburst(rng, t0):
    out, _ = scen_normal(rng, t0)
    tgt = "192.168.1.5"
    rate = rng.choice([100, 300, 1000, 3000])
    dur = rng.choice([5, 8, 15])
    spoof = rng.random() < 0.5
    start = t0 + 10
    for i in range(rate * dur):
        src = (f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
               if spoof else "192.168.1.110")
        out.append(pkt(start + i / rate, src, tgt, rng.randint(1025, 65000), 80, "S"))
    return out, start


def scen_bruteforce(rng, t0):
    out, _ = scen_normal(rng, t0)
    atk, tgt = "192.168.1.120", "192.168.1.5"
    rate = rng.choice([1, 2, 3, 5])  # attempts per second
    n = rng.randint(25, 120)
    start = t0 + 10
    for i in range(n):
        out += handshake(start + i / rate, atk, tgt, 22, rng)[:3]
    return out, start


def scen_slowscan(rng, t0):
    out, _ = scen_normal(rng, t0)
    atk, tgt = "192.168.1.130", "192.168.1.5"
    start = t0 + 10
    for i, p in enumerate(rng.sample(range(1, 1024), 40)):
        out.append(pkt(start + i * 12.0, atk, tgt, 50000 + i, p, "S"))  # 1 probe / 12 s
    return out, start


SCENARIOS = {
    # name: (function, attack types expected, category)
    "normal":      (scen_normal, [], "core"),
    "busy_benign": (scen_busy_benign, [], "core"),
    "portscan":    (scen_portscan, ["port_scan"], "core"),
    "synburst":    (scen_synburst, ["syn_burst"], "core"),
    "bruteforce":  (scen_bruteforce, ["repeat_conn"], "core"),
    "slowscan":    (scen_slowscan, ["port_scan"], "evasion"),
}


def main():
    os.makedirs(OUT, exist_ok=True)
    rng = random.Random(SEED)
    manifest = []
    for name, (fn, expected, cat) in SCENARIOS.items():
        for run in range(RUNS):
            t0 = 1_700_000_000 + run * 1000
            packets, start = fn(rng, t0)
            packets.sort(key=lambda p: p.time)
            path = os.path.join(OUT, f"{name}_{run:02d}.pcap")
            w = PcapWriter(path, sync=True)
            for p in packets:
                w.write(p)
            w.close()
            manifest.append({"file": path, "scenario": name, "expected": expected,
                             "category": cat, "attack_start": start, "packets": len(packets)})
    with open(os.path.join(OUT, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Wrote {len(manifest)} PCAP files to {OUT}/")


if __name__ == "__main__":
    sys.exit(main())
