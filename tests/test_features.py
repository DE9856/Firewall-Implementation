"""IPv6, REJECT, rule analysis and previews, IDS controls, connections,
session history, exports, and the dashboard endpoints for them."""

import json
import shutil
import struct
import tempfile
import unittest
import urllib.request
from pathlib import Path

from firewall.analysis import analyse, preview
from firewall.engine import Firewall
from firewall.export import pcap, report
from firewall.history import History
from firewall.monitor import Monitor
from firewall.packet import (ACK, RST, SYN, build_icmp, build_tcp, build_udp, checksum, dissect,
                             parse_packet, reject_reply)
from firewall.pcap import read_pcap
from firewall.rules import config_from_dict, load_config
from firewall.server import serve
from firewall.traffic import TrafficGenerator

ROOT = Path(__file__).resolve().parent.parent
HOST, EXT = "192.168.1.10", "45.33.32.156"
HOST6, EXT6, LAN6 = "2001:db8:1::10", "2001:db8:beef::7", "2001:db8:1::25"


def fw_with(rules, **extra):
    return Firewall(config_from_dict({"local_networks": ["192.168.1.0/24", "2001:db8:1::/64"],
                                      "rules": rules, **extra}))


class IPv6Tests(unittest.TestCase):
    def test_parse_build_roundtrip(self):
        p = parse_packet(build_tcp(EXT6, HOST6, 4000, 443, SYN, b"hi", seq=99))
        self.assertEqual((p.version, p.src_ip, p.dst_ip, p.dst_port, p.seq, p.payload_len), (6, EXT6, HOST6, 443, 99, 2))
        u = parse_packet(build_udp(HOST6, "2001:db8:53::53", 5000, 53, b"q"))
        self.assertEqual((u.proto_name, u.dst_port, u.length), ("udp", 53, 40 + 9))

    def test_icmpv6_checksum_covers_pseudo_header(self):
        raw = build_icmp(EXT6, HOST6)                     # defaults to an echo request
        pkt = parse_packet(raw)
        self.assertTrue(pkt.is_echo_request)
        pseudo = raw[8:40] + struct.pack("!I3xB", len(raw) - 40, 58)
        self.assertEqual(checksum(pseudo + raw[40:]), 0)

    def test_extension_headers_are_walked(self):
        tcp = build_tcp(EXT6, HOST6, 1, 22, SYN)
        hop_by_hop = bytes([6, 0]) + b"\x01\x04\x00\x00\x00\x00"      # next = TCP, 8 bytes, PadN
        raw = bytearray(tcp[:40] + hop_by_hop + tcp[40:])
        raw[6] = 0                                                   # next header: hop-by-hop
        raw[4:6] = struct.pack("!H", len(raw) - 40)
        pkt = parse_packet(bytes(raw))
        self.assertEqual((pkt.protocol, pkt.dst_port, pkt.header_len), (6, 22, 48))
        self.assertEqual([l["layer"] for l in dissect(bytes(raw))], ["IPv6", "IPv6 hop-by-hop options", "TCP"])

    def test_rules_and_state_apply_to_ipv6(self):
        fw = Firewall(load_config(ROOT / "config" / "rules.json"))
        self.assertEqual(fw.process(build_tcp(LAN6, HOST6, 1, 22, SYN), "in").verdict, "ACCEPT")
        self.assertEqual(fw.process(build_tcp(EXT6, HOST6, 1, 22, SYN), "in").verdict, "DROP")
        self.assertEqual(fw.process(build_tcp(HOST6, EXT6, 2, 443, SYN), "out").verdict, "ACCEPT")
        d = fw.process(build_tcp(EXT6, HOST6, 443, 2, SYN | ACK), "in")
        self.assertEqual((d.verdict, d.stage), ("ACCEPT", "conntrack"))
        self.assertEqual(fw.process(build_icmp(EXT6, HOST6, 129), "in").stage, "conntrack")   # unsolicited reply

    def test_ipv6_ping_flood_is_detected(self):
        fw = Firewall(load_config(ROOT / "config" / "rules.json"))
        alerts = [fw.process(build_icmp(EXT6, HOST6), "in").ids_alert for _ in range(12)]
        self.assertTrue(any(a and a.startswith("ICMP flood") for a in alerts))


class RejectTests(unittest.TestCase):
    def test_tcp_syn_gets_rst_ack(self):
        pkt = parse_packet(build_tcp(EXT, HOST, 4000, 23, SYN, seq=1000))
        raw, what = reject_reply(pkt, b"")
        r = parse_packet(raw)
        self.assertEqual((what, r.src_ip, r.dst_ip, r.src_port, r.dst_port), ("TCP RST", HOST, EXT, 23, 4000))
        self.assertEqual((r.flag_str, r.ack), ("AR", 1001))

    def test_errors_are_never_answered(self):
        self.assertIsNone(reject_reply(parse_packet(build_tcp(EXT, HOST, 1, 23, RST)), b""))
        self.assertIsNone(reject_reply(parse_packet(build_icmp(EXT, HOST, 3, 3)), b""))

    def test_udp_gets_port_unreachable_quoting_the_packet(self):
        orig = build_udp(EXT, HOST, 5000, 161, b"x" * 30)
        raw, what = reject_reply(parse_packet(orig), orig)
        r = parse_packet(raw)
        self.assertEqual((what, r.icmp_type, r.icmp_code), ("ICMP port unreachable", 3, 3))
        self.assertEqual(raw[28:28 + 28], orig[:28])               # original IP header + 8 bytes
        orig6 = build_udp(EXT6, HOST6, 5000, 161)
        r6 = parse_packet(reject_reply(parse_packet(orig6), orig6)[0])
        self.assertEqual((r6.protocol, r6.icmp_type, r6.icmp_code), (58, 1, 4))

    def test_engine_rejects_and_sends(self):
        fw = fw_with([{"action": "REJECT", "direction": "out", "protocol": "tcp", "dst_port": 23}])
        sent = []
        fw.reply_sender = sent.append
        d = fw.process(build_tcp(HOST, EXT, 5000, 23, SYN), "out")
        self.assertEqual((d.verdict, d.reject, len(sent)), ("DROP", "TCP RST", 1))
        self.assertEqual(parse_packet(sent[0]).dst_ip, HOST)


class AnalysisTests(unittest.TestCase):
    def rules(self, specs):
        return config_from_dict({"local_networks": ["192.168.1.0/24"], "rules": specs}).rules

    def test_shadowed_and_redundant(self):
        rules = self.rules([
            {"id": 1, "action": "DROP", "direction": "in", "protocol": "tcp", "dst_port": "1-1024"},
            {"id": 2, "action": "ACCEPT", "direction": "in", "protocol": "tcp", "dst_port": 22, "src": "$LAN"},
            {"id": 3, "action": "DROP", "direction": "in", "protocol": "tcp", "dst_port": [80, 443]},
            {"id": 4, "action": "ACCEPT", "direction": "in", "protocol": "tcp", "dst_port": 8080},
        ])
        found = analyse(rules)
        self.assertEqual((found[2]["kind"], found[2]["by"]), ("shadowed", 1))
        self.assertEqual((found[3]["kind"], found[3]["by"]), ("redundant", 1))
        self.assertNotIn(4, found)

    def test_narrower_earlier_rule_does_not_shadow(self):
        rules = self.rules([
            {"id": 1, "action": "ACCEPT", "src": "10.0.0.0/24"},
            {"id": 2, "action": "DROP", "src": "10.0.0.0/8"},
            {"id": 3, "action": "DROP", "protocol": "tcp", "tcp_flags": "S"},
            {"id": 4, "action": "ACCEPT", "protocol": "tcp", "tcp_flags": "SA"},   # SYN+ACK packets have S set
            {"id": 5, "action": "ACCEPT", "protocol": "tcp", "tcp_flags": "S!S"},
        ])
        found = analyse(rules)
        self.assertNotIn(2, found)
        self.assertEqual(found[4]["by"], 3)
        self.assertEqual(found[5]["kind"], "never")

    def test_disabled_rules_shadow_nothing_and_shipped_config_is_clean(self):
        rules = self.rules([{"id": 1, "action": "DROP", "enabled": False}, {"id": 2, "action": "ACCEPT"}])
        self.assertEqual(analyse(rules), {})
        self.assertEqual(analyse(load_config(ROOT / "config" / "rules.json").rules), {})

    def test_preview_shows_changed_verdicts(self):
        fw = Firewall(load_config(ROOT / "config" / "rules.json"))
        mon = Monitor(fw, {"kind": "simulated"})
        for i in range(3):
            fw.process(build_tcp(EXT, HOST, 4000 + i, 80, SYN), "in")      # allowed by rule 6
        fw.process(build_tcp(EXT, HOST, 4100, 3389, SYN), "in")           # dropped by rule 7
        draft = [r for r in fw.cfg.rules if r.id != 6]
        res = preview(fw, list(mon.packets), draft)
        self.assertEqual((res["checked"], res["nowBlocked"], res["nowAllowed"]), (4, 3, 0))
        g = res["groups"][0]
        self.assertEqual((g["src"], g["port"], g["before"], g["after"], g["beforeBy"], g["afterBy"]),
                         (EXT, 80, "ACCEPT", "DROP", 6, None))


class IdsControlTests(unittest.TestCase):
    def test_configure_ban_unban(self):
        fw = Firewall(load_config(ROOT / "config" / "rules.json"))
        fw.ids.configure({"port_scan": {"threshold": 3, "window": 2}})
        alerts = [fw.process(build_tcp(EXT, HOST, 5000 + p, p, SYN), "in").ids_alert for p in range(1, 6)]
        self.assertTrue(alerts[3].startswith("port scan"))
        self.assertTrue(fw.ids.unban(EXT))
        self.assertEqual(fw.process(build_tcp(EXT, HOST, 1, 80, SYN), "in").stage, "ids")   # counter still full
        fw.ids.ban("8.8.4.4", fw.clock(), 30, "banned by hand")
        self.assertEqual(fw.process(build_tcp("8.8.4.4", HOST, 1, 80, SYN), "in").stage, "ids_ban")


class ConnectionsAndHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_connections_listed_with_state_and_counts(self):
        fw = Firewall(load_config(ROOT / "config" / "rules.json"))
        mon = Monitor(fw, {"kind": "simulated"})
        fw.process(build_tcp(HOST, EXT, 5000, 443, SYN), "out")
        fw.process(build_tcp(EXT, HOST, 443, 5000, SYN | ACK), "in")
        c = mon.connections()
        self.assertEqual(c["total"], 1)
        conn = c["connections"][0]
        self.assertEqual((conn["state"], conn["packets"], conn["replies"], conn["outbound"]), ("ESTABLISHED", 2, 1, True))

    def test_history_survives_restart(self):
        db = self.tmp / "h.sqlite"
        fw = Firewall(load_config(ROOT / "config" / "rules.json"))
        mon = Monitor(fw, {"kind": "simulated", "label": "one"}, history=History(db, "one"))
        fw.process(build_tcp(EXT, HOST, 1, 3389, SYN), "in")
        mon._save_history()
        first_id = mon.held[-1]["id"]
        fw2 = Firewall(load_config(ROOT / "config" / "rules.json"))
        mon2 = Monitor(fw2, {"kind": "simulated", "label": "two"}, history=History(db, "two"))
        self.assertEqual(mon2.held[-1]["id"], first_id)
        self.assertIn("Rule 7 dropped traffic", [e["title"] for e in mon2.events])
        fw2.process(build_tcp(EXT, HOST, 2, 3389, SYN), "in")
        self.assertGreater(mon2.packets[-1]["id"], first_id)             # numbers stay unique
        self.assertEqual(len(mon2.history.sessions()), 2)

    def test_exports(self):
        fw = Firewall(load_config(ROOT / "config" / "rules.json"))
        mon = Monitor(fw, {"kind": "simulated", "label": "test"})
        fw.process(build_tcp(EXT, HOST, 1, 3389, SYN), "in")
        fw.process(build_tcp(EXT6, HOST6, 1, 22, SYN), "in")
        path = self.tmp / "b.pcap"
        path.write_bytes(pcap(list(mon.held)))
        got = [parse_packet(raw) for _, raw in read_pcap(str(path))]
        self.assertEqual([(p.version, p.dst_port) for p in got], [(4, 3389), (6, 22)])
        text = report(mon.snapshot(), analyse(fw.cfg.rules))
        self.assertIn("# PyWall session report", text)
        self.assertIn(f"`{EXT}`", text)


class FeatureServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.cfg_path = cls.tmp / "rules.json"
        shutil.copy(ROOT / "config" / "rules.json", cls.cfg_path)
        cls.fw = Firewall(load_config(cls.cfg_path))
        cls.mon = Monitor(cls.fw, {"kind": "simulated", "label": "test"})
        cls.gen = TrafficGenerator(cls.fw, seed=1)
        cls.httpd = serve(cls.fw, cls.mon, str(cls.cfg_path), port=0, generator=cls.gen)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.tmp)

    def call(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"X-PyWall": "1", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                raw = r.read()
                return r.status, json.loads(raw) if r.headers.get_content_type() == "application/json" else raw
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_preview_changes_nothing(self):
        self.fw.process(build_tcp(EXT, HOST, 9, 80, SYN), "in")
        before = self.cfg_path.read_text()
        code, res = self.call("POST", "/api/rules/preview", {"op": "delete", "id": 6})
        self.assertEqual(code, 200)
        self.assertGreaterEqual(res["nowBlocked"], 1)
        self.assertEqual(self.cfg_path.read_text(), before)
        self.assertIn(6, [r.id for r in self.fw.cfg.rules])
        code, res = self.call("POST", "/api/rules/preview",
                              {"op": "create", "position": 1, "spec": {"action": "DROP", "protocol": "tcp"}})
        self.assertEqual(code, 200)
        self.assertTrue(any(f["kind"] == "shadowed" for f in res["findings"].values()))

    def test_ids_settings_saved(self):
        code, res = self.call("PUT", "/api/ids", {"port_scan": {"threshold": 25, "window": 5}})
        self.assertEqual((code, res["ids"]["port_scan"]["threshold"]), (200, 25))
        self.assertEqual(json.loads(self.cfg_path.read_text())["ids"]["port_scan"]["threshold"], 25)
        code, res = self.call("PUT", "/api/ids", {"syn_flood": {"threshold": -1, "window": 1}})
        self.assertEqual(code, 400)

    def test_ban_and_unban(self):
        code, _ = self.call("POST", "/api/bans", {"src": "2001:db8::bad", "seconds": 30})
        self.assertEqual(code, 200)
        self.assertEqual(self.fw.process(build_tcp("2001:db8::bad", HOST6, 1, 80, SYN), "in").stage, "ids_ban")
        self.assertEqual(self.call("DELETE", "/api/bans/2001:db8::bad")[0], 200)
        self.assertEqual(self.call("DELETE", "/api/bans/2001:db8::bad")[0], 404)
        self.assertEqual(self.call("POST", "/api/bans", {"src": "nope"})[0], 400)

    def test_attack_and_cooldown(self):
        code, res = self.call("POST", "/api/attack", {"kind": "port_scan"})
        self.assertEqual((code, res["packets"]), (200, 30))
        self.assertEqual(len(self.gen.queue), 30)
        self.assertEqual(self.call("POST", "/api/attack", {"kind": "syn_flood"})[0], 429)

    def test_connections_and_exports(self):
        self.fw.process(build_tcp(HOST, EXT, 7000, 443, SYN), "out")
        code, res = self.call("GET", "/api/connections")
        self.assertEqual(code, 200)
        self.assertTrue(any(c["dport"] == 443 for c in res["connections"]))
        code, body = self.call("GET", "/api/export/blocked.pcap")
        self.assertEqual((code, body[:4]), (200, b"\xd4\xc3\xb2\xa1"))
        code, body = self.call("GET", "/api/export/report.md")
        self.assertTrue(body.startswith(b"# PyWall session report"))


if __name__ == "__main__":
    unittest.main()
