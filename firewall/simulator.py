"""Traffic simulator: builds real IPv4 packets for a set of attack and
normal-traffic scenarios and runs them through the firewall with a virtual
clock. Used for demonstrations and as an end-to-end test (no root needed)."""

from __future__ import annotations

from dataclasses import dataclass

from .colors import paint
from .engine import Firewall
from .packet import ACK, FIN, PSH, SYN, build_icmp, build_tcp, build_udp

HOST = "192.168.1.10"        # the machine being protected
LAN_PC = "192.168.1.25"
WEB = "142.250.183.14"       # some public web server
DNS = "8.8.8.8"
STRANGER = "45.33.32.156"
ATTACKER = "203.0.113.66"
FLOODER = "198.51.100.77"
BAD = "185.220.101.5"        # on the blacklist
HOST6 = "2001:db8:1::10"     # the same machine's IPv6 address
LAN6 = "2001:db8:1::25"
WEB6 = "2001:db8:cafe::443"
STRANGER6 = "2001:db8:beef::7"


@dataclass
class Step:
    scenario: str
    raw: bytes
    direction: str
    expect: str
    dt: float = 0.01          # virtual seconds elapsed before this packet
    quiet: bool = False       # don't print (used for bulk flood packets)


class VirtualClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def scenarios() -> list[Step]:
    s: list[Step] = []
    add = s.append

    sc = "1. Outbound HTTPS + stateful reply"
    add(Step(sc, build_tcp(HOST, WEB, 51000, 443, SYN), "out", "ACCEPT"))
    add(Step(sc, build_tcp(WEB, HOST, 443, 51000, SYN | ACK), "in", "ACCEPT"))
    add(Step(sc, build_tcp(HOST, WEB, 51000, 443, ACK), "out", "ACCEPT"))
    add(Step(sc, build_tcp(WEB, HOST, 443, 51000, PSH | ACK, b"HTTP/1.1 200 OK"), "in", "ACCEPT"))
    add(Step(sc, build_tcp(HOST, WEB, 51000, 443, FIN | ACK), "out", "ACCEPT"))

    sc = "2. DNS query and reply"
    add(Step(sc, build_udp(HOST, DNS, 53001, 53, b"\x12\x34query"), "out", "ACCEPT"))
    add(Step(sc, build_udp(DNS, HOST, 53, 53001, b"\x12\x34answer"), "in", "ACCEPT"))

    sc = "3. SSH: LAN allowed, internet blocked"
    add(Step(sc, build_tcp(LAN_PC, HOST, 40000, 22, SYN), "in", "ACCEPT"))
    add(Step(sc, build_tcp(STRANGER, HOST, 40001, 22, SYN), "in", "DROP"))

    sc = "4. Public web server on port 80"
    add(Step(sc, build_tcp(STRANGER, HOST, 40002, 80, SYN), "in", "ACCEPT"))

    sc = "5. Closed / dangerous ports"
    add(Step(sc, build_tcp(STRANGER, HOST, 40003, 3389, SYN), "in", "DROP"))
    add(Step(sc, build_tcp(STRANGER, HOST, 40004, 445, SYN), "in", "DROP"))
    add(Step(sc, build_udp(STRANGER, HOST, 40005, 161), "in", "DROP"))
    add(Step(sc, build_tcp(HOST, STRANGER, 51001, 23, SYN), "out", "DROP"))

    sc = "6. Spoofed / unsolicited packets"
    add(Step(sc, build_tcp(STRANGER, HOST, 443, 51999, ACK), "in", "DROP"))
    add(Step(sc, build_icmp(STRANGER, HOST, icmp_type=0), "in", "DROP"))
    add(Step(sc, build_udp(STRANGER, HOST, 53, 53999), "in", "DROP"))

    sc = "7. Blacklisted address"
    add(Step(sc, build_tcp(BAD, HOST, 40006, 80, SYN), "in", "DROP"))

    sc = "8. Ping with rate limit (5/s)"
    for i in range(7):
        add(Step(sc, build_icmp(STRANGER, HOST), "in", "ACCEPT" if i < 5 else "DROP", dt=0.01))
    add(Step(sc, build_icmp(STRANGER, HOST), "in", "ACCEPT", dt=1.0))

    sc = "9. Port scan detection"
    # 20 SYNs to ports 20-39: dropped by the rules anyway, but on the 16th
    # distinct port the IDS bans the attacker ...
    for i, port in enumerate(range(20, 40)):
        add(Step(sc, build_tcp(ATTACKER, HOST, 60000 + i, port, SYN), "in", "DROP", dt=0.05, quiet=i not in (0, 14, 15, 19)))
    # ... so even port 80, normally open to everyone, is now refused
    add(Step(sc, build_tcp(ATTACKER, HOST, 60100, 80, SYN), "in", "DROP", dt=1.0))

    sc = "10. SYN flood detection"
    for i in range(25):
        add(Step(sc, build_tcp(FLOODER, HOST, 30000 + i, 80, SYN), "in",
                 "ACCEPT" if i < 20 else "DROP", dt=0.01, quiet=i not in (0, 19, 20, 24)))

    sc = "11. Malformed packet"
    add(Step(sc, b"\x45\x00\x00", "in", "DROP"))

    sc = "12. IPv6: the same rules, the same state tracking"
    add(Step(sc, build_tcp(HOST6, WEB6, 52000, 443, SYN), "out", "ACCEPT"))
    add(Step(sc, build_tcp(WEB6, HOST6, 443, 52000, SYN | ACK), "in", "ACCEPT"))
    add(Step(sc, build_tcp(LAN6, HOST6, 41000, 22, SYN), "in", "ACCEPT"))
    add(Step(sc, build_tcp(STRANGER6, HOST6, 41001, 22, SYN), "in", "DROP"))
    add(Step(sc, build_icmp(STRANGER6, HOST6, 128), "in", "ACCEPT"))
    add(Step(sc, build_icmp(STRANGER6, HOST6, 129), "in", "DROP"))

    sc = "13. REJECT: telnet out is refused with a TCP RST"
    add(Step(sc, build_tcp(HOST, STRANGER, 51002, 23, SYN), "out", "DROP"))
    return s


def run_simulation(fw: Firewall, clock: VirtualClock, verbose: bool = False) -> bool:
    current = None
    passed = failed = 0
    for step in scenarios():
        clock.t += step.dt
        d = fw.process(step.raw, step.direction)
        ok = d.verdict == step.expect
        passed += ok
        failed += not ok
        if step.scenario != current:
            current = step.scenario
            print(f"\n{paint(current, 'bold', 'bright_blue')}")
        if verbose or not step.quiet or not ok:
            summary = d.packet.summary() if d.packet else "<malformed bytes>"
            mark = paint("ok  ", "green") if ok else paint("FAIL", "bold", "red")
            reason = paint(d.reason, "yellow") if "IDS" in d.reason else d.reason
            if d.reject:
                reason += paint(f"  -> sent a {d.reject} back", "grey")
            print(f"  {mark} {step.direction:>3} {summary:<58} {paint.verdict(d.verdict)} {reason}")
    result = f"Simulation: {passed} passed, {failed} failed ({passed + failed} packets)"
    print("\n" + paint(result, "bold", "green" if failed == 0 else "red"))
    print(fw.report())
    return failed == 0
