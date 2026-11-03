#!/usr/bin/env python3
"""
NetSentinel - Network Attack Detection and Security Auditing Tool (v1.0)

Rule-based detection of three TCP-level behaviours from PCAP files or live traffic:
  1. Port scan            - many unique destination ports from one source to one target
  2. SYN burst            - many TCP SYN packets towards one destination in a short window
  3. Repeated connections - many connection attempts to the same service (src, dst, port)

Only "pure SYN" packets (SYN set, ACK clear) are counted, so normal handshake
replies (SYN-ACK) never contribute to a detection.

Usage examples:
  python3 netsentinel.py capture.pcap
  python3 netsentinel.py capture.pcap --csv out.csv --json out.json --pdf out.pdf
  python3 netsentinel.py capture.pcap --config thresholds.json --whitelist 192.168.1.1
  sudo python3 netsentinel.py --live eth0 --duration 60 --pdf live_report.pdf

Use only on networks you own or are explicitly authorised to monitor.
"""
import argparse
import csv
import datetime as dt
import json
import sys
from collections import Counter, defaultdict, deque

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "port_scan":   {"threshold": 15,  "window": 10, "severity": "High"},
    "syn_burst":   {"threshold": 100, "window": 5,  "severity": "High"},
    "repeat_conn": {"threshold": 20,  "window": 30, "severity": "Medium"},
    "whitelist": [],
}

KIND_NAMES = {
    "port_scan": "Port scan",
    "syn_burst": "SYN burst",
    "repeat_conn": "Repeated connections",
}

COUNTERMEASURES = {
    "port_scan": ("Close or filter unnecessary exposed ports; block or rate-limit the "
                  "source at the firewall; monitor the source for follow-up activity."),
    "syn_burst": ("Enable SYN cookies and connection rate limiting; apply firewall "
                  "filtering upstream; verify service availability."),
    "repeat_conn": ("Review the targeted service's logs (for example SSH authentication "
                    "logs); enforce rate limiting or temporary bans (for example fail2ban); "
                    "require key-based authentication."),
}

DESCRIPTIONS = {
    "port_scan": "{obs} unique destination ports probed within {win}s",
    "syn_burst": "{obs} TCP SYN packets within {win}s",
    "repeat_conn": "{obs} connection attempts within {win}s",
}


def load_config(path=None):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if path:
        with open(path) as f:
            user = json.load(f)
        for k, v in user.items():
            if isinstance(v, dict) and k in cfg:
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg


def risk_score(observed, threshold):
    """0-100 score: exactly at threshold = 50, twice the threshold or more = 100."""
    return max(0, min(100, int(round(50.0 * observed / threshold))))


# ----------------------------------------------------------------------------
# Detection engine (independent of Scapy so it is easy to unit-test)
# ----------------------------------------------------------------------------
class Detector:
    def __init__(self, config=None):
        self.cfg = config or load_config()
        self.whitelist = set(self.cfg.get("whitelist", []))
        self.scan = {}                     # (src, dst)        -> (deque[(ts, dport)], Counter of ports)
        self.burst = defaultdict(deque)    # dst               -> deque[ts]
        self.repeat = defaultdict(deque)   # (src, dst, dport) -> deque[ts]
        self.active = {}                   # (kind, key)       -> alert dict
        self.alerts = []
        self.stats = {"packets": 0, "tcp": 0, "syn": 0, "first_ts": None, "last_ts": None}
        self.syn_by_src = Counter()
        self._purge_counter = 0

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def is_pure_syn(flags):
        flags = int(flags)
        return bool(flags & 0x02) and not (flags & 0x10)

    def _raise(self, kind, key, ts, observed, src, dst, port=None):
        c = self.cfg[kind]
        alert = self.active.get((kind, key))
        if alert is not None and ts - alert["end_ts"] <= c["window"]:
            # same ongoing episode: extend it instead of creating a duplicate
            alert["end_ts"] = ts
            if observed > alert["observed"]:
                alert["observed"] = observed
                alert["risk"] = risk_score(observed, c["threshold"])
            return
        alert = {
            "kind": kind, "type": KIND_NAMES[kind], "severity": c["severity"],
            "source": src, "target": dst if port is None else f"{dst}:{port}",
            "start_ts": ts, "end_ts": ts, "observed": observed,
            "risk": risk_score(observed, c["threshold"]),
            "window": c["window"], "threshold": c["threshold"],
            "countermeasure": COUNTERMEASURES[kind],
        }
        self.active[(kind, key)] = alert
        self.alerts.append(alert)

    def _purge(self, ts):
        """Free memory for idle keys (called periodically)."""
        maxw = max(self.cfg[k]["window"] for k in KIND_NAMES)
        for k in [k for k, (q, _) in self.scan.items() if not q or ts - q[-1][0] > maxw]:
            del self.scan[k]
        for table in (self.burst, self.repeat):
            for k in [k for k, q in table.items() if not q or ts - q[-1] > maxw]:
                del table[k]

    # -- main entry point ----------------------------------------------------
    def process(self, ts, src, dst, dport, flags, is_tcp=True):
        st = self.stats
        st["packets"] += 1
        if st["first_ts"] is None:
            st["first_ts"] = ts
        st["last_ts"] = ts
        if not is_tcp:
            return
        st["tcp"] += 1
        if not self.is_pure_syn(flags):
            return
        st["syn"] += 1
        if src in self.whitelist:
            return
        self.syn_by_src[src] += 1

        # Module 1: port scan
        c = self.cfg["port_scan"]
        entry = self.scan.get((src, dst))
        if entry is None:
            entry = self.scan[(src, dst)] = (deque(), Counter())
        q, ports = entry
        q.append((ts, dport))
        ports[dport] += 1
        while q and ts - q[0][0] > c["window"]:
            _, old_port = q.popleft()
            ports[old_port] -= 1
            if ports[old_port] <= 0:
                del ports[old_port]
        uniq = len(ports)
        if uniq >= c["threshold"]:
            self._raise("port_scan", (src, dst), ts, uniq, src, dst)

        # Module 2: SYN burst (per destination, any number of sources)
        c = self.cfg["syn_burst"]
        q = self.burst[dst]
        q.append(ts)
        while q and ts - q[0] > c["window"]:
            q.popleft()
        if len(q) >= c["threshold"]:
            self._raise("syn_burst", dst, ts, len(q), src, dst)

        # Module 3: repeated connection attempts to the same service
        c = self.cfg["repeat_conn"]
        q = self.repeat[(src, dst, dport)]
        q.append(ts)
        while q and ts - q[0] > c["window"]:
            q.popleft()
        if len(q) >= c["threshold"]:
            self._raise("repeat_conn", (src, dst, dport), ts, len(q), src, dst, dport)

        self._purge_counter += 1
        if self._purge_counter >= 50000:
            self._purge_counter = 0
            self._purge(ts)

    def finalize(self):
        for a in self.alerts:
            a["evidence"] = DESCRIPTIONS[a["kind"]].format(obs=a["observed"], win=a["window"])
            a["duration"] = round(a["end_ts"] - a["start_ts"], 3)
        return self.alerts


# ----------------------------------------------------------------------------
# Input: PCAP file or live capture (Scapy is imported lazily)
# ----------------------------------------------------------------------------
def analyze_pcap(path, config=None):
    from scapy.all import PcapReader, IP, TCP
    det = Detector(config)
    with PcapReader(path) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ts = float(pkt.time)
            if TCP in pkt:
                det.process(ts, pkt[IP].src, pkt[IP].dst, pkt[TCP].dport, pkt[TCP].flags)
            else:
                det.process(ts, pkt[IP].src, pkt[IP].dst, None, 0, is_tcp=False)
    return det


def analyze_live(iface, duration, config=None):
    from scapy.all import sniff, IP, TCP
    det = Detector(config)
    seen = [0]

    def handle(pkt):
        if IP not in pkt:
            return
        ts = float(pkt.time)
        if TCP in pkt:
            before = len(det.alerts)
            det.process(ts, pkt[IP].src, pkt[IP].dst, pkt[TCP].dport, pkt[TCP].flags)
            if len(det.alerts) > before:
                a = det.alerts[-1]
                print(f"[LIVE ALERT] [{a['severity']}] {a['type']}: {a['source']} -> "
                      f"{a['target']} (observed {a['observed']})", flush=True)
        else:
            det.process(ts, pkt[IP].src, pkt[IP].dst, None, 0, is_tcp=False)

    print(f"Capturing on {iface} for {duration}s (Ctrl+C to stop early)...")
    try:
        sniff(iface=iface, prn=handle, store=False, timeout=duration)
    except KeyboardInterrupt:
        pass
    return det


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
def fmt_ts(ts):
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def write_csv(alerts, path):
    cols = ["start_time", "type", "severity", "risk", "source", "target",
            "evidence", "duration_s", "countermeasure"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for a in alerts:
            w.writerow([fmt_ts(a["start_ts"]), a["type"], a["severity"], a["risk"],
                        a["source"], a["target"], a["evidence"], a["duration"],
                        a["countermeasure"]])


def write_json(det, path):
    out = {"stats": det.stats, "top_sources": det.syn_by_src.most_common(10),
           "config": det.cfg, "findings": det.alerts}
    with open(path, "w") as f:
        json.dump(out, f, indent=2, default=str)


def write_pdf(det, path, source_name):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    small = ss["BodyText"].clone("small", fontSize=8, leading=10)
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=1.5 * cm, rightMargin=1.5 * cm,
                            topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    el = [Paragraph("NetSentinel Security Audit Report", ss["Title"]),
          Paragraph(f"Source: {source_name}<br/>Generated: "
                    f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ss["BodyText"]),
          Spacer(1, 10)]

    st = det.stats
    dur = (st["last_ts"] - st["first_ts"]) if st["first_ts"] is not None else 0
    sev = Counter(a["severity"] for a in det.alerts)
    el.append(Paragraph("1. Summary", ss["Heading2"]))
    summary = [["Packets analysed", st["packets"]], ["TCP packets", st["tcp"]],
               ["Pure SYN packets", st["syn"]], ["Capture duration (s)", f"{dur:.1f}"],
               ["Total findings", len(det.alerts)], ["High severity", sev.get("High", 0)],
               ["Medium severity", sev.get("Medium", 0)], ["Low severity", sev.get("Low", 0)]]
    t = Table(summary, colWidths=[7 * cm, 5 * cm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                           ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke)]))
    el += [t, Spacer(1, 10)]

    el.append(Paragraph("2. Top SYN sources", ss["Heading2"]))
    rows = [["Source IP", "SYN packets"]] + [[s, n] for s, n in det.syn_by_src.most_common(5)]
    t = Table(rows, colWidths=[7 * cm, 5 * cm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
    el += [t, Spacer(1, 10)]

    el.append(Paragraph("3. Findings", ss["Heading2"]))
    if not det.alerts:
        el.append(Paragraph("No suspicious activity matched the configured rules.", ss["BodyText"]))
    else:
        rows = [["Time", "Type", "Sev.", "Risk", "Source -> Target", "Evidence"]]
        for a in det.alerts:
            rows.append([Paragraph(fmt_ts(a["start_ts"]), small), Paragraph(a["type"], small),
                         a["severity"], a["risk"],
                         Paragraph(f"{a['source']} -> {a['target']}", small),
                         Paragraph(a["evidence"], small)])
        t = Table(rows, repeatRows=1, colWidths=[3 * cm, 2.8 * cm, 1.4 * cm, 1.1 * cm, 4.6 * cm, 4.6 * cm])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        el += [t, Spacer(1, 10), Paragraph("4. Recommended countermeasures", ss["Heading2"])]
        for kind in dict.fromkeys(a["kind"] for a in det.alerts):
            el.append(Paragraph(f"<b>{KIND_NAMES[kind]}:</b> {COUNTERMEASURES[kind]}", ss["BodyText"]))
    el += [Spacer(1, 12), Paragraph(
        "Note: detections are rule-based indicators of suspicious behaviour, not proof of an "
        "attack. Review each finding in context before acting.", small)]
    doc.build(el)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="NetSentinel - rule-based network attack detection")
    ap.add_argument("pcap", nargs="?", help="PCAP file to analyse")
    ap.add_argument("--live", metavar="IFACE", help="capture live from an interface (needs root)")
    ap.add_argument("--duration", type=int, default=60, help="live capture seconds (default 60)")
    ap.add_argument("--config", help="JSON file overriding thresholds")
    ap.add_argument("--whitelist", nargs="*", default=[], help="trusted source IPs to ignore")
    ap.add_argument("--csv", help="write CSV report")
    ap.add_argument("--json", help="write JSON report")
    ap.add_argument("--pdf", help="write PDF report")
    args = ap.parse_args(argv)

    if not args.pcap and not args.live:
        ap.error("provide a PCAP file or --live IFACE")
    cfg = load_config(args.config)
    cfg["whitelist"] = list(set(cfg.get("whitelist", [])) | set(args.whitelist))

    det = analyze_live(args.live, args.duration, cfg) if args.live else analyze_pcap(args.pcap, cfg)
    alerts = det.finalize()
    name = args.live and f"live:{args.live}" or args.pcap

    print(f"\nNetSentinel: {det.stats['packets']} packets, {det.stats['syn']} pure SYN packets analysed")
    for a in alerts:
        print(f"[{a['severity']:6}] {a['type']:21} {a['source']:>15} -> {a['target']:<22} "
              f"risk={a['risk']:3}  {a['evidence']}")
    print(f"{len(alerts)} finding(s).")
    if args.csv:
        write_csv(alerts, args.csv)
    if args.json:
        write_json(det, args.json)
    if args.pdf:
        write_pdf(det, args.pdf, name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
