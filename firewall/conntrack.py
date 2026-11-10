"""Connection tracking: remembers flows the firewall has allowed so that
reply traffic is accepted automatically (a *stateful* firewall).

States reported for a packet:
  NEW          - the packet can legitimately open a flow (TCP SYN, UDP, ICMP/ICMPv6 echo request)
  ESTABLISHED  - the packet belongs to a flow already accepted (either direction)
  INVALID      - e.g. a TCP ACK/FIN/RST, or an ICMP echo reply, with no known flow
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .packet import ACK, FIN, PROTO_TCP, PROTO_UDP, RST, SYN, Packet

NEW, ESTABLISHED, INVALID = "NEW", "ESTABLISHED", "INVALID"

TIMEOUTS = {
    "tcp_syn": 30,          # half-open handshake
    "tcp_established": 3600,
    "tcp_closing": 10,
    "udp": 60,
    "icmp": 30,
}


@dataclass
class Flow:
    key: tuple
    proto: int
    state: str
    last_seen: float
    timeout: float
    packets: int = 1
    bytes: int = 0
    created: float = 0.0                      # engine clock when the flow was accepted
    wall: float = field(default_factory=time.time)   # wall clock at creation, for display
    replies: int = 0                          # packets seen in the reverse direction


def _key(pkt: Packet) -> tuple:
    if pkt.is_icmp:
        return (pkt.protocol, pkt.src_ip, 0, pkt.dst_ip, 0)
    return (pkt.protocol, pkt.src_ip, pkt.src_port or 0, pkt.dst_ip, pkt.dst_port or 0)


def _reverse(key: tuple) -> tuple:
    proto, a, ap, b, bp = key
    return (proto, b, bp, a, ap)


class ConnTrack:
    def __init__(self, max_entries: int = 65536):
        self.flows: dict[tuple, Flow] = {}
        self.max_entries = max_entries

    def __len__(self):
        return len(self.flows)

    # ------------------------------------------------------------------ lookup
    def _find(self, pkt: Packet) -> Flow | None:
        key = _key(pkt)
        if pkt.is_icmp:
            # only an echo *reply* travelling back belongs to a ping "flow";
            # every new echo request is judged (and rate limited) by the rules
            return self.flows.get(_reverse(key)) if pkt.is_echo_reply else None
        return self.flows.get(key) or self.flows.get(_reverse(key))

    def lookup(self, pkt: Packet, now: float) -> tuple[str, Flow | None]:
        flow = self._find(pkt)
        if flow and now - flow.last_seen > flow.timeout:
            self._remove(flow)
            flow = None
        if flow:
            return ESTABLISHED, flow
        if self._can_open(pkt):
            return NEW, None
        return INVALID, None

    def peek(self, pkt: Packet, now: float) -> tuple[str, Flow | None]:
        """Like lookup(), but changes nothing (for explanations)."""
        flow = self._find(pkt)
        if flow and now - flow.last_seen <= flow.timeout:
            return ESTABLISHED, flow
        return (NEW if self._can_open(pkt) else INVALID), None

    @staticmethod
    def _can_open(pkt: Packet) -> bool:
        if pkt.protocol == PROTO_TCP:
            return pkt.has_flag(SYN) and not pkt.has_flag(ACK) and not pkt.has_flag(RST)
        if pkt.is_icmp:
            return not pkt.is_echo_reply       # an echo reply never opens a flow
        return True                            # UDP and other protocols

    # ------------------------------------------------------------------ update
    def track_new(self, pkt: Packet, now: float) -> None:
        if len(self.flows) >= self.max_entries:
            self.expire(now)
            if len(self.flows) >= self.max_entries:
                oldest = min(self.flows.values(), key=lambda f: f.last_seen)
                self._remove(oldest)
        if pkt.protocol == PROTO_TCP and not pkt.has_flag(SYN):
            state, timeout = "ESTABLISHED", TIMEOUTS["tcp_established"]    # picked up mid-stream
        elif pkt.protocol == PROTO_TCP:
            state, timeout = "SYN_SENT", TIMEOUTS["tcp_syn"]
        elif pkt.protocol == PROTO_UDP:
            state, timeout = "UDP", TIMEOUTS["udp"]
        else:
            state, timeout = "ICMP", TIMEOUTS["icmp"]
        key = _key(pkt)
        self.flows[key] = Flow(key, pkt.protocol, state, now, timeout, bytes=pkt.length, created=now)

    def update(self, flow: Flow, pkt: Packet, now: float) -> None:
        flow.last_seen = now
        flow.packets += 1
        flow.bytes += pkt.length
        if _key(pkt) != flow.key:
            flow.replies += 1
        if flow.proto != PROTO_TCP:
            return
        if pkt.has_flag(RST):
            self._remove(flow)
        elif pkt.has_flag(FIN):
            flow.state, flow.timeout = "CLOSING", TIMEOUTS["tcp_closing"]
        elif flow.state == "SYN_SENT" and pkt.has_flag(SYN) and pkt.has_flag(ACK):
            flow.state, flow.timeout = "ESTABLISHED", TIMEOUTS["tcp_established"]

    def expire(self, now: float) -> int:
        dead = [f for f in self.flows.values() if now - f.last_seen > f.timeout]
        for f in dead:
            self._remove(f)
        return len(dead)

    def _remove(self, flow: Flow) -> None:
        self.flows.pop(flow.key, None)
