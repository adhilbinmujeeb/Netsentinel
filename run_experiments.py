#!/usr/bin/env python3
"""Run NetSentinel over the labelled PCAPs and compute evaluation metrics."""
import json
import statistics
import time
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scapy.all import IP, TCP, PcapReader

from netsentinel import Detector, load_config, KIND_NAMES

# Alerts of these kinds are expected side effects of the attack itself (not false positives):
TOLERATED = {"portscan": {"syn_burst"}, "synburst": {"repeat_conn"}}
KINDS = list(KIND_NAMES)


import pickle, os, struct, socket


def load_packets(path):
    """Fast parser for classic PCAP files with Ethernet/IPv4/TCP (as written by generate_traffic.py)."""
    cache = path + ".pkl"
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    rows = []
    with open(path, "rb") as f:
        magic = f.read(24)[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, frac, caplen, _ = struct.unpack(endian + "IIII", h)
            d = f.read(caplen)
            ts = sec + frac / (1e9 if nano else 1e6)
            if len(d) < 34 or d[12:14] != b"\x08\x00":
                continue
            ihl = (d[14] & 0x0F) * 4
            src, dst = socket.inet_ntoa(d[26:30]), socket.inet_ntoa(d[30:34])
            if d[23] == 6 and len(d) >= 14 + ihl + 14:
                t = 14 + ihl
                rows.append((ts, src, dst, struct.unpack("!H", d[t + 2:t + 4])[0], d[t + 13], True))
            else:
                rows.append((ts, src, dst, None, 0, False))
    pickle.dump(rows, open(cache, "wb"))
    return rows


def run(rows, cfg):
    det = Detector(cfg)
    for r in rows:
        det.process(*r)
    return det.finalize()


def evaluate(runs, cfg, kinds=KINDS):
    """Per-detector confusion matrix over core runs."""
    cm = {k: dict(TP=0, FN=0, FP=0, TN=0) for k in kinds}
    for m, rows in runs:
        if m["category"] != "core":
            continue
        fired = {a["kind"] for a in run(rows, cfg)}
        for k in kinds:
            pos = k in m["expected"]
            if not pos and k in TOLERATED.get(m["scenario"], set()):
                continue
            hit = k in fired
            cm[k]["TP" if pos and hit else "FN" if pos else "FP" if hit else "TN"] += 1
    return cm


def rates(c):
    dr = 100.0 * c["TP"] / (c["TP"] + c["FN"]) if c["TP"] + c["FN"] else float("nan")
    fpr = 100.0 * c["FP"] / (c["FP"] + c["TN"]) if c["FP"] + c["TN"] else float("nan")
    prec = 100.0 * c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else float("nan")
    return dr, fpr, prec


def main():
    manifest = json.load(open("lab_pcaps/manifest.json"))
    t = time.time()
    runs = [(m, load_packets(m["file"])) for m in manifest]
    total_pkts = sum(len(r) for _, r in runs)
    print(f"Loaded {len(runs)} pcaps, {total_pkts} packets in {time.time() - t:.1f}s")

    cfg = load_config()
    out = {"config": {k: cfg[k] for k in KINDS}}

    # --- throughput of the detection engine alone
    t = time.time()
    for _, rows in runs:
        run(rows, cfg)
    el = time.time() - t
    out["throughput_pps"] = int(total_pkts / el)
    out["total_packets"] = total_pkts

    # --- scenario x detector alert matrix, and detection time
    matrix = defaultdict(lambda: {k: 0 for k in KINDS})
    runs_per = defaultdict(int)
    dtimes = defaultdict(list)
    alert_counts = defaultdict(list)
    for m, rows in runs:
        alerts = run(rows, cfg)
        sc = m["scenario"]
        runs_per[sc] += 1
        alert_counts[sc].append(len(alerts))
        for k in {a["kind"] for a in alerts}:
            matrix[sc][k] += 1
        for a in alerts:
            if a["kind"] in m["expected"] and m["attack_start"] is not None:
                dtimes[sc].append(a["start_ts"] - m["attack_start"])
                break
    out["scenario_matrix"] = {sc: dict(v, runs=runs_per[sc]) for sc, v in matrix.items()}
    out["alerts_per_run_mean"] = {sc: round(statistics.mean(v), 2) for sc, v in alert_counts.items()}
    out["detection_time_s"] = {sc: {"mean": round(statistics.mean(v), 2), "min": round(min(v), 2),
                                    "max": round(max(v), 2), "n": len(v)}
                               for sc, v in dtimes.items()}

    # --- core confusion matrices
    cm = evaluate(runs, cfg)
    out["confusion"] = {k: dict(v, DR=round(rates(v)[0], 1), FPR=round(rates(v)[1], 1),
                                precision=round(rates(v)[2], 1)) for k, v in cm.items()}
    tot = {x: sum(cm[k][x] for k in KINDS) for x in ("TP", "FN", "FP", "TN")}
    dr, fpr, prec = rates(tot)
    out["overall"] = dict(tot, DR=round(dr, 1), FPR=round(fpr, 1), precision=round(prec, 1))

    # --- evasion (slow scan) detection
    slow = [(m, r) for m, r in runs if m["scenario"] == "slowscan"]
    out["slowscan_detected"] = sum(1 for m, r in slow if any(a["kind"] == "port_scan" for a in run(r, cfg)))
    out["slowscan_runs"] = len(slow)
    # the same slow scan against a longer window
    cfg2 = load_config()
    cfg2["port_scan"].update(window=600)
    out["slowscan_detected_window600"] = sum(
        1 for m, r in slow if any(a["kind"] == "port_scan" for a in run(r, cfg2)))
    slow_fp = 0
    norm = [(m, r) for m, r in runs if m["category"] == "core" and m["scenario"] in ("normal", "busy_benign")]
    for m, r in norm:
        if any(a["kind"] == "port_scan" for a in run(r, cfg2)):
            slow_fp += 1
    out["window600_portscan_fp_on_benign"] = slow_fp
    out["benign_runs"] = len(norm)

    # --- threshold sensitivity for each detector
    sens = {}
    grids = {"port_scan": [3, 5, 8, 10, 15, 20, 30, 50],
             "syn_burst": [20, 50, 75, 100, 150, 300, 500, 1000],
             "repeat_conn": [5, 8, 10, 15, 20, 30, 50, 80]}
    for k, grid in grids.items():
        sens[k] = []
        for th in grid:
            c2 = load_config()
            c2[k]["threshold"] = th
            r = rates(evaluate(runs, c2, [k])[k])
            sens[k].append({"threshold": th, "DR": round(r[0], 1), "FPR": round(r[1], 1)})
    out["sensitivity"] = sens

    json.dump(out, open("results.json", "w"), indent=2)

    # --- charts
    fig, ax = plt.subplots(figsize=(7, 3.6))
    names = [KIND_NAMES[k] for k in KINDS]
    ax.bar(names, [out["confusion"][k]["DR"] for k in KINDS], color="#2b6cb0", label="Detection rate (%)")
    ax.bar([n for n in names], [out["confusion"][k]["FPR"] for k in KINDS], color="#c53030",
           width=0.35, label="False positive rate (%)")
    ax.set_ylim(0, 105)
    ax.set_ylabel("Percent")
    ax.set_title("NetSentinel detection and false positive rates (default thresholds)")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig("chart_rates.png", dpi=160)

    fig, axes = plt.subplots(1, 3, figsize=(11, 3.4))
    for ax, k in zip(axes, KINDS):
        xs = [s["threshold"] for s in sens[k]]
        ax.plot(xs, [s["DR"] for s in sens[k]], "o-", color="#2b6cb0", label="Detection rate")
        ax.plot(xs, [s["FPR"] for s in sens[k]], "s--", color="#c53030", label="False positive rate")
        ax.axvline(cfg[k]["threshold"], color="grey", ls=":", label="default")
        ax.set_xscale("log")
        ax.set_title(KIND_NAMES[k])
        ax.set_xlabel("Threshold")
        ax.set_ylim(-3, 105)
    axes[0].set_ylabel("Percent")
    axes[0].legend(fontsize=7)
    fig.tight_layout()
    fig.savefig("chart_sensitivity.png", dpi=160)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
