import json
import unittest
from pathlib import Path

from firewall.engine import Firewall
from firewall.packet import ACK, PSH, RST, SYN, build_tcp
from firewall.rules import RuleError, config_from_dict, load_config

ROOT = Path(__file__).resolve().parent.parent


class LanTokenTests(unittest.TestCase):
    def test_lan_follows_local_networks(self):
        cfg = load_config(ROOT / "config" / "rules.json", lan=["10.42.0.0/24"])
        ssh_lan = next(r for r in cfg.rules if r.spec.get("src") == "$LAN")
        self.assertEqual([str(n) for n in ssh_lan.src], ["10.42.0.0/24"])
        fw = Firewall(cfg)
        self.assertEqual(fw.process(build_tcp("10.42.0.7", "10.42.0.1", 5000, 22, SYN), "in").verdict, "ACCEPT")
        self.assertEqual(fw.process(build_tcp("192.168.1.25", "10.42.0.1", 5001, 22, SYN), "in").verdict, "DROP")

    def test_lan_without_networks_is_an_error(self):
        with self.assertRaises(RuleError):
            config_from_dict({"rules": [{"action": "ACCEPT", "src": "$LAN"}]})

    def test_token_kept_in_spec_for_saving(self):
        cfg = load_config(ROOT / "config" / "rules.json")
        self.assertIn("$LAN", json.dumps([r.spec for r in cfg.rules]))


class PickupTests(unittest.TestCase):
    HOST, WEB = "192.168.1.26", "142.250.183.14"

    def fw(self, pickup=True):
        return Firewall(config_from_dict({"local_networks": ["192.168.1.0/24"], "pickup_outbound": pickup,
                                          "rules": [{"action": "ACCEPT", "direction": "out"}]}))

    def test_open_connection_is_adopted_from_its_outbound_side(self):
        fw = self.fw()
        reply = build_tcp(self.WEB, self.HOST, 443, 51000, PSH | ACK)
        self.assertEqual(fw.process(reply, "in").verdict, "DROP")           # nothing known yet
        out = fw.process(build_tcp(self.HOST, self.WEB, 51000, 443, ACK), "out")
        self.assertEqual((out.verdict, out.stage), ("ACCEPT", "rule"))      # judged by the rules
        again = fw.process(reply, "in")
        self.assertEqual((again.verdict, again.stage), ("ACCEPT", "conntrack"))

    def test_inbound_stray_packets_still_dropped(self):
        fw = self.fw()
        for _ in range(3):
            self.assertEqual(fw.process(build_tcp(self.WEB, self.HOST, 443, 52000, ACK), "in").reason,
                             "invalid state (no matching connection)")

    def test_rst_is_not_adopted(self):
        fw = self.fw()
        self.assertEqual(fw.process(build_tcp(self.HOST, self.WEB, 51001, 443, RST), "out").stage, "conntrack")

    def test_pickup_can_be_switched_off(self):
        fw = self.fw(pickup=False)
        self.assertEqual(fw.process(build_tcp(self.HOST, self.WEB, 51002, 443, ACK), "out").verdict, "DROP")


if __name__ == "__main__":
    unittest.main()
