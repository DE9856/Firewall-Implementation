import json
import shutil
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from firewall.engine import Firewall
from firewall.explain import explain
from firewall.monitor import Monitor
from firewall.packet import ACK, SYN, build_icmp, build_tcp, build_udp, dissect, parse_packet
from firewall.rules import load_config
from firewall.server import serve

ROOT = Path(__file__).resolve().parent.parent
HOST, EXT = "192.168.1.10", "45.33.32.156"


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.fw = Firewall(load_config(ROOT / "config" / "rules.json"))

    def test_stage_and_header_recorded(self):
        d = self.fw.process(build_tcp(EXT, HOST, 4000, 22, SYN), "in")
        self.assertEqual((d.verdict, d.stage, d.direction), ("DROP", "rule", "in"))
        self.assertEqual(d.header[:1], b"\x45")
        self.assertEqual(self.fw.process(b"\x45\x00", "in").stage, "parse")

    def test_disabled_rule_is_skipped(self):
        web = next(r for r in self.fw.cfg.rules if r.id == 6)
        web.enabled = False
        self.assertEqual(self.fw.process(build_tcp(EXT, HOST, 4001, 80, SYN), "in").reason, "default policy")

    def test_explain_agrees_with_decide_and_changes_nothing(self):
        cases = [build_tcp(EXT, HOST, 1, 22, SYN), build_tcp(EXT, HOST, 1, 80, SYN),
                 build_tcp(EXT, HOST, 443, 5, ACK), build_udp(EXT, HOST, 1, 161),
                 build_icmp(EXT, HOST, 8), build_tcp(HOST, EXT, 5, 23, SYN)]
        for raw in cases:
            pkt = parse_packet(raw)
            direction = "out" if pkt.src_ip == HOST else "in"
            hits = [r.hits for r in self.fw.cfg.rules]
            e = explain(self.fw, pkt, direction)
            self.assertEqual([r.hits for r in self.fw.cfg.rules], hits)
            d = self.fw.process(raw, direction)
            self.assertEqual((e["verdict"], e["stage"]), (d.verdict, d.stage), pkt.summary())

    def test_rule_conditions_explain_mismatch(self):
        rule = next(r for r in self.fw.cfg.rules if r.id == 4)
        conds = rule.conditions(parse_packet(build_tcp(EXT, HOST, 1, 22, SYN)), "in")
        self.assertEqual([c["ok"] for c in conds if c["field"] == "source"], [False])

    def test_dissect_fields(self):
        layers = dissect(build_tcp(EXT, HOST, 1234, 80, SYN | ACK, seq=7))
        self.assertEqual([l["layer"] for l in layers], ["IPv4", "TCP"])
        fields = {f["name"]: f["value"] for f in layers[1]["fields"]}
        self.assertEqual((fields["Destination port"], fields["Sequence number"], fields["Flags"]), (80, 7, "SYN ACK"))
        ip = {f["name"]: f for f in layers[0]["fields"]}
        self.assertEqual(ip["Header checksum"]["note"], "valid")


class MonitorTests(unittest.TestCase):
    def test_events_and_counters(self):
        fw = Firewall(load_config(ROOT / "config" / "rules.json"))
        mon = Monitor(fw, {"kind": "simulated"})
        for i in range(25):                     # SYN flood -> one IDS event, then coalesced ban events
            fw.process(build_tcp("198.51.100.77", HOST, 3000 + i, 80, SYN), "in")
        kinds = [e["kind"] for e in mon.events]
        self.assertEqual(kinds.count("ids"), 1)
        ban = [e for e in mon.events if e["kind"] == "ban"]
        self.assertEqual(len(ban), 1)
        self.assertEqual(ban[0]["count"], 4)
        s = mon.stats()
        self.assertEqual((s["accepted"], s["dropped"], s["total"]), (20, 5, 25))
        self.assertEqual(sum(f["count"] for f in mon.flows()), 25)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.cfg_path = cls.tmp / "rules.json"
        shutil.copy(ROOT / "config" / "rules.json", cls.cfg_path)
        cls.fw = Firewall(load_config(cls.cfg_path))
        cls.mon = Monitor(cls.fw, {"kind": "simulated"})
        cls.httpd = serve(cls.fw, cls.mon, str(cls.cfg_path), port=0)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.tmp)

    def call(self, method, path, body=None, guard=True):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if guard:
            req.add_header("X-PyWall", "1")
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_rule_lifecycle_persists_and_takes_effect(self):
        spec = {"name": "test block 9999", "action": "DROP", "direction": "in", "protocol": "tcp", "dst_port": 9999}
        code, res = self.call("POST", "/api/rules", {"spec": spec, "position": 1})
        self.assertEqual(code, 200)
        rid = res["id"]
        self.assertEqual(self.fw.cfg.rules[0].id, rid)
        saved = json.loads(self.cfg_path.read_text())["rules"]
        self.assertEqual(saved[0]["name"], "test block 9999")
        self.assertEqual(self.fw.process(build_tcp(EXT, HOST, 1, 9999, SYN), "in").rule.id, rid)
        code, _ = self.call("PUT", f"/api/rules/{rid}", {"spec": {**spec, "enabled": False}})
        self.assertEqual(code, 200)
        self.assertFalse(self.fw.cfg.rules[0].enabled)
        ids = [r.id for r in self.fw.cfg.rules]
        code, _ = self.call("POST", "/api/rules/order", {"ids": ids[1:] + ids[:1]})
        self.assertEqual((code, self.fw.cfg.rules[-1].id), (200, rid))
        code, _ = self.call("DELETE", f"/api/rules/{rid}")
        self.assertEqual(code, 200)
        self.assertNotIn(rid, [r.id for r in self.fw.cfg.rules])
        titles = [e["title"] for e in self.mon.events]
        self.assertIn(f"Rule {rid} created", titles)
        self.assertIn(f"Rule {rid} disabled", titles)
        self.assertIn(f"Rule {rid} deleted", titles)

    def test_invalid_rule_rejected_and_nothing_changes(self):
        before = self.cfg_path.read_text()
        code, res = self.call("POST", "/api/rules", {"spec": {"action": "ACCEPT", "protocol": "tcp", "dst_port": 70000}})
        self.assertEqual(code, 400)
        self.assertIn("invalid port", res["error"])
        self.assertEqual(self.cfg_path.read_text(), before)

    def test_mutations_need_guard_header(self):
        code, _ = self.call("DELETE", "/api/rules/1", guard=False)
        self.assertEqual(code, 403)

    def test_state_and_packet_detail(self):
        self.fw.process(build_tcp(EXT, HOST, 1, 3389, SYN), "in")
        code, state = self.call("GET", "/api/state")
        self.assertEqual(code, 200)
        pid = state["packets"][-1]["id"]
        code, detail = self.call("GET", f"/api/packets/{pid}")
        self.assertEqual((code, detail["explain"]["stage"]), (200, "rule"))


class ReadOnlyTests(unittest.TestCase):
    def test_public_demo_refuses_changes_but_explains(self):
        fw = Firewall(load_config(ROOT / "config" / "rules.json"))
        mon = Monitor(fw, {"kind": "simulated", "readOnly": True})
        httpd = serve(fw, mon, None, port=0, read_only=True)
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            def call(method, path, body):
                req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method=method,
                                             headers={"X-PyWall": "1", "Content-Type": "application/json"})
                try:
                    with urllib.request.urlopen(req, timeout=5) as r:
                        return r.status, json.loads(r.read())
                except urllib.error.HTTPError as e:
                    return e.code, json.loads(e.read())
            before = [r.id for r in fw.cfg.rules]
            code, res = call("DELETE", "/api/rules/1", {})
            self.assertEqual(code, 403)
            self.assertIn("read-only", res["error"])
            self.assertEqual(call("POST", "/api/rules", {"spec": {"action": "DROP"}})[0], 403)
            self.assertEqual([r.id for r in fw.cfg.rules], before)
            code, res = call("POST", "/api/explain", {"proto": "tcp", "src": EXT, "dst": HOST, "sport": 1, "dport": 22, "dir": "in"})
            self.assertEqual((code, res["verdict"]), (200, "DROP"))
            with urllib.request.urlopen(base + "/api/health", timeout=5) as r:
                self.assertEqual(json.loads(r.read()), {"ok": True})
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
