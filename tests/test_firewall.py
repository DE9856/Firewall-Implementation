import os
import struct
import tempfile
import unittest

from firewall.engine import Firewall
from firewall.packet import (ACK, FIN, RST, SYN, PacketError, build_icmp, build_tcp,
                             build_udp, checksum, parse_packet)
from firewall.pcap import read_pcap
from firewall.rules import RuleError, TokenBucket, config_from_dict, load_config

HOST, LAN, EXT = "192.168.1.10", "192.168.1.25", "8.8.4.4"


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def make_fw(rules, **extra):
    cfg = config_from_dict({"default_policy": "DROP", "local_networks": ["192.168.1.0/24"],
                            "rules": rules, **extra})
    clock = Clock()
    return Firewall(cfg, clock_fn=clock), clock


class PacketTests(unittest.TestCase):
    def test_tcp_round_trip(self):
        p = parse_packet(build_tcp(HOST, EXT, 1234, 443, SYN | ACK))
        self.assertEqual((p.src_ip, p.dst_ip, p.src_port, p.dst_port), (HOST, EXT, 1234, 443))
        self.assertTrue(p.has_flag(SYN) and p.has_flag(ACK))
        self.assertEqual(p.proto_name, "tcp")

    def test_udp_and_icmp(self):
        u = parse_packet(build_udp(HOST, EXT, 5000, 53))
        self.assertEqual((u.protocol, u.dst_port), (17, 53))
        i = parse_packet(build_icmp(EXT, HOST, icmp_type=8))
        self.assertEqual((i.protocol, i.icmp_type), (1, 8))

    def test_ip_checksum_valid(self):
        raw = build_tcp(HOST, EXT, 1, 2)
        self.assertEqual(checksum(raw[:20]), 0)   # a correct header sums to 0

    def test_malformed(self):
        with self.assertRaises(PacketError):
            parse_packet(b"\x45\x00")
        with self.assertRaises(PacketError):
            parse_packet(b"\x60" + b"\x00" * 39)  # IPv6


class RuleTests(unittest.TestCase):
    def test_first_match_wins(self):
        fw, _ = make_fw([{"action": "DROP", "protocol": "tcp", "dst_port": 80},
                         {"action": "ACCEPT", "protocol": "tcp"}])
        self.assertEqual(fw.process(build_tcp(EXT, HOST, 1, 80)).verdict, "DROP")
        self.assertEqual(fw.process(build_tcp(EXT, HOST, 1, 81)).verdict, "ACCEPT")

    def test_default_policy(self):
        fw, _ = make_fw([])
        d = fw.process(build_udp(EXT, HOST, 1, 9999))
        self.assertEqual((d.verdict, d.reason), ("DROP", "default policy"))

    def test_cidr_and_port_ranges(self):
        fw, _ = make_fw([{"action": "ACCEPT", "protocol": "tcp", "src": "192.168.1.0/24",
                          "dst_port": ["8000-8100", 22]}])
        self.assertEqual(fw.process(build_tcp(LAN, HOST, 1, 8050)).verdict, "ACCEPT")
        self.assertEqual(fw.process(build_tcp(LAN, HOST, 2, 22)).verdict, "ACCEPT")
        self.assertEqual(fw.process(build_tcp(LAN, HOST, 3, 8101)).verdict, "DROP")
        self.assertEqual(fw.process(build_tcp(EXT, HOST, 4, 8050)).verdict, "DROP")

    def test_direction(self):
        fw, _ = make_fw([{"action": "ACCEPT", "direction": "out"}])
        self.assertEqual(fw.process(build_udp(HOST, EXT, 1, 53), "out").verdict, "ACCEPT")
        self.assertEqual(fw.process(build_udp(EXT, HOST, 1, 54), "in").verdict, "DROP")

    def test_tcp_flag_match(self):
        fw, _ = make_fw([{"action": "ACCEPT", "protocol": "tcp", "tcp_flags": "S!A"}], stateful=False)
        self.assertEqual(fw.process(build_tcp(EXT, HOST, 1, 80, SYN)).verdict, "ACCEPT")
        self.assertEqual(fw.process(build_tcp(EXT, HOST, 1, 80, SYN | ACK)).verdict, "DROP")

    def test_invalid_rules_rejected(self):
        for bad in ({"action": "ALLOW"}, {"action": "ACCEPT", "protocol": "gre"},
                    {"action": "ACCEPT", "dst_port": 80},
                    {"action": "ACCEPT", "protocol": "tcp", "dst_port": 70000},
                    {"action": "ACCEPT", "src": "300.1.1.1"}):
            with self.assertRaises(RuleError, msg=bad):
                config_from_dict({"rules": [bad]})

    def test_shipped_config_loads(self):
        cfg = load_config(os.path.join(os.path.dirname(__file__), "..", "config", "rules.json"))
        self.assertGreater(len(cfg.rules), 5)

    def test_token_bucket(self):
        b = TokenBucket(2, 1, now=0)
        self.assertEqual([b.take(0), b.take(0), b.take(0)], [True, True, False])
        self.assertTrue(b.take(0.5))       # half a second refills one token


class StatefulTests(unittest.TestCase):
    def setUp(self):
        self.fw, self.clock = make_fw([{"action": "ACCEPT", "direction": "out"}])

    def test_reply_allowed_only_after_request(self):
        reply = build_tcp(EXT, HOST, 443, 5000, SYN | ACK)
        self.assertEqual(self.fw.process(reply, "in").verdict, "DROP")
        self.fw.process(build_tcp(HOST, EXT, 5000, 443, SYN), "out")
        d = self.fw.process(reply, "in")
        self.assertEqual((d.verdict, d.reason), ("ACCEPT", "established connection"))

    def test_rst_closes_connection(self):
        self.fw.process(build_tcp(HOST, EXT, 5000, 443, SYN), "out")
        self.fw.process(build_tcp(EXT, HOST, 443, 5000, RST), "in")
        self.assertEqual(len(self.fw.conntrack), 0)
        self.assertEqual(self.fw.process(build_tcp(EXT, HOST, 443, 5000, ACK), "in").verdict, "DROP")

    def test_fin_shortens_timeout_and_expiry(self):
        self.fw.process(build_tcp(HOST, EXT, 5000, 443, SYN), "out")
        self.fw.process(build_tcp(HOST, EXT, 5000, 443, FIN | ACK), "out")
        self.clock.t += 11
        self.assertEqual(self.fw.process(build_tcp(EXT, HOST, 443, 5000, ACK), "in").verdict, "DROP")

    def test_udp_reply(self):
        self.fw.process(build_udp(HOST, EXT, 40000, 53), "out")
        self.assertEqual(self.fw.process(build_udp(EXT, HOST, 53, 40000), "in").verdict, "ACCEPT")
        self.assertEqual(self.fw.process(build_udp(EXT, HOST, 53, 40001), "in").verdict, "DROP")

    def test_ping_reply(self):
        self.fw.process(build_icmp(HOST, EXT, 8), "out")
        self.assertEqual(self.fw.process(build_icmp(EXT, HOST, 0), "in").verdict, "ACCEPT")


class SecurityTests(unittest.TestCase):
    def test_blacklist_beats_rules(self):
        fw, _ = make_fw([{"action": "ACCEPT"}], blacklist=["10.66.0.0/16"])
        self.assertEqual(fw.process(build_tcp("10.66.1.1", HOST, 1, 80)).reason, "blacklisted source")

    def test_whitelist_beats_ids(self):
        fw, _ = make_fw([], whitelist=[LAN], ids={"port_scan": {"threshold": 2}})
        for port in range(10):
            self.assertEqual(fw.process(build_tcp(LAN, HOST, 1, port)).verdict, "ACCEPT")

    def test_port_scan_ban_and_expiry(self):
        fw, clock = make_fw([{"action": "ACCEPT", "protocol": "tcp", "dst_port": 80}],
                            ids={"block_seconds": 30, "port_scan": {"threshold": 5, "window": 5}})
        for port in range(1, 7):
            clock.t += 0.1
            fw.process(build_tcp(EXT, HOST, 1000 + port, port, SYN))
        self.assertIn(EXT, fw.ids.blocked)
        self.assertEqual(fw.process(build_tcp(EXT, HOST, 2000, 80, SYN)).verdict, "DROP")
        clock.t += 31
        self.assertEqual(fw.process(build_tcp(EXT, HOST, 2001, 80, SYN)).verdict, "ACCEPT")

    def test_syn_flood(self):
        fw, clock = make_fw([{"action": "ACCEPT", "protocol": "tcp", "dst_port": 80}],
                            ids={"syn_flood": {"threshold": 10, "window": 1}})
        verdicts = []
        for i in range(15):
            clock.t += 0.01
            verdicts.append(fw.process(build_tcp(EXT, HOST, 3000 + i, 80, SYN)).verdict)
        self.assertEqual(verdicts.count("ACCEPT"), 10)

    def test_slow_traffic_not_flagged(self):
        fw, clock = make_fw([{"action": "ACCEPT", "protocol": "tcp", "dst_port": 80}],
                            ids={"syn_flood": {"threshold": 10, "window": 1}})
        for i in range(50):
            clock.t += 0.5
            self.assertEqual(fw.process(build_tcp(EXT, HOST, 3000 + i, 80, SYN)).verdict, "ACCEPT")

    def test_rate_limited_ping(self):
        fw, clock = make_fw([{"action": "ACCEPT", "protocol": "icmp", "icmp_type": 8, "rate_limit": "3/s"}])
        got = [fw.process(build_icmp(EXT, HOST)).verdict for _ in range(5)]
        self.assertEqual(got, ["ACCEPT"] * 3 + ["DROP"] * 2)


class PcapTests(unittest.TestCase):
    def test_read_ethernet_pcap(self):
        pkts = [build_tcp(EXT, HOST, 1, 80, SYN), build_udp(HOST, EXT, 2, 53)]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for i, ip in enumerate(pkts):
                frame = b"\x00" * 12 + b"\x08\x00" + ip
                f.write(struct.pack("<IIII", 10 + i, 0, len(frame), len(frame)) + frame)
            arp = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28        # non-IP frame is skipped
            f.write(struct.pack("<IIII", 20, 0, len(arp), len(arp)) + arp)
        try:
            got = list(read_pcap(f.name))
        finally:
            os.unlink(f.name)
        self.assertEqual([raw for _, raw in got], pkts)


class SimulationTest(unittest.TestCase):
    def test_all_scenarios_pass(self):
        import contextlib
        import io
        from firewall.simulator import VirtualClock, run_simulation
        cfg = load_config(os.path.join(os.path.dirname(__file__), "..", "config", "rules.json"))
        clock = VirtualClock()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(run_simulation(Firewall(cfg, clock_fn=clock), clock))


if __name__ == "__main__":
    unittest.main()
