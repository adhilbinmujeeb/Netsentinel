"""Unit tests: python3 -m unittest -v test_netsentinel"""
import unittest
from netsentinel import Detector, load_config

SYN, SYNACK, ACK = 0x02, 0x12, 0x10


def feed(det, events):
    for ts, src, dst, port, flags in events:
        det.process(ts, src, dst, port, flags)
    return det.finalize()


class TestDetector(unittest.TestCase):
    def test_port_scan_detected(self):
        a = feed(Detector(), [(i * 0.1, "1.1.1.1", "2.2.2.2", 1000 + i, SYN) for i in range(20)])
        self.assertEqual([x["kind"] for x in a], ["port_scan"])

    def test_below_threshold_no_alert(self):
        a = feed(Detector(), [(i * 0.1, "1.1.1.1", "2.2.2.2", 1000 + i, SYN) for i in range(14)])
        self.assertEqual(a, [])

    def test_syn_ack_ignored(self):
        a = feed(Detector(), [(i * 0.01, "2.2.2.2", "1.1.1.1", 1000 + i, SYNACK) for i in range(500)])
        self.assertEqual(a, [])

    def test_syn_burst_from_many_sources(self):
        ev = [(i * 0.01, f"9.9.{i % 250}.{i % 200 + 1}", "2.2.2.2", 80, SYN) for i in range(150)]
        self.assertIn("syn_burst", [x["kind"] for x in feed(Detector(), ev)])

    def test_repeated_connections(self):
        a = feed(Detector(), [(i, "1.1.1.1", "2.2.2.2", 22, SYN) for i in range(25)])
        self.assertEqual([x["kind"] for x in a], ["repeat_conn"])
        self.assertEqual(a[0]["target"], "2.2.2.2:22")

    def test_one_alert_per_episode_and_new_episode_later(self):
        ev = [(i * 0.1, "1.1.1.1", "2.2.2.2", 1000 + i, SYN) for i in range(60)]
        ev += [(500 + i * 0.1, "1.1.1.1", "2.2.2.2", 2000 + i, SYN) for i in range(60)]
        self.assertEqual(len(feed(Detector(), ev)), 2)

    def test_whitelist(self):
        cfg = load_config()
        cfg["whitelist"] = ["1.1.1.1"]
        a = feed(Detector(cfg), [(i * 0.1, "1.1.1.1", "2.2.2.2", 1000 + i, SYN) for i in range(40)])
        self.assertEqual(a, [])

    def test_slow_scan_evades_default_window(self):
        a = feed(Detector(), [(i * 12.0, "1.1.1.1", "2.2.2.2", 1 + i, SYN) for i in range(40)])
        self.assertEqual(a, [])

    def test_risk_score_scales(self):
        a = feed(Detector(), [(i * 0.05, "1.1.1.1", "2.2.2.2", 1000 + i, SYN) for i in range(40)])
        self.assertEqual(a[0]["risk"], 100)

    def test_config_override(self):
        cfg = load_config()
        cfg["port_scan"]["threshold"] = 5
        a = feed(Detector(cfg), [(i * 0.1, "1.1.1.1", "2.2.2.2", 1000 + i, SYN) for i in range(6)])
        self.assertEqual([x["kind"] for x in a], ["port_scan"])


if __name__ == "__main__":
    unittest.main()
