"""The decision engine: every packet goes through the same pipeline and
gets an ACCEPT or DROP verdict.

    parse -> whitelist -> blacklist / IDS bans -> IDS inspection
          -> connection state -> rule table (first match) -> default policy
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from .colors import paint
from .conntrack import ESTABLISHED, INVALID, NEW, ConnTrack
from .ids import IntrusionDetector
from .packet import RST, Packet, PacketError, parse_packet
from .rules import Config, Rule, now as clock

log = logging.getLogger("firewall")


# Pipeline stages, in order. Decision.stage names the one that decided.
STAGES = ("parse", "whitelist", "blacklist", "ids_ban", "ids", "conntrack", "rule", "policy")
HEADER_BYTES = 60          # bytes of each packet kept for inspection (IPv4 + TCP headers)


@dataclass
class Decision:
    verdict: str            # ACCEPT | DROP
    reason: str
    packet: Packet | None
    rule: Rule | None = None
    state: str | None = None
    stage: str = "policy"
    direction: str | None = None
    ids_alert: str | None = None       # set when this packet triggered an IDS ban
    rate_limited: bool = False
    time: float = field(default_factory=time.time)   # wall clock, for display
    header: bytes = b""


class Firewall:
    def __init__(self, config: Config, clock_fn=clock):
        self.cfg = config
        self.clock = clock_fn
        self.conntrack = ConnTrack()
        self.ids = IntrusionDetector(config.ids)
        self.stats = Counter()
        self._last_expire = 0.0
        # Observers (the dashboard) are called with every Decision. The lock
        # guards engine state when packets and API requests come from threads.
        self.listeners: list[Callable[[Decision], None]] = []
        self.lock = threading.RLock()

    # ----------------------------------------------------------------- helpers
    def direction_of(self, pkt: Packet) -> str:
        if not self.cfg.local_networks:
            return "in"
        dst = ipaddress.ip_address(pkt.dst_ip)
        return "in" if any(dst in n for n in self.cfg.local_networks) else "out"

    @staticmethod
    def _in(ip: str, nets) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in nets)

    # ---------------------------------------------------------------- pipeline
    def process(self, raw: bytes, direction: str | None = None) -> Decision:
        try:
            pkt = parse_packet(raw)
        except PacketError as exc:
            return self._finish(Decision("DROP", f"malformed packet: {exc}", None, stage="parse",
                                         direction=direction, header=bytes(raw[:HEADER_BYTES])))
        d = self.decide(pkt, direction, _raw=raw)
        return d

    def decide(self, pkt: Packet, direction: str | None = None, _raw: bytes = b"") -> Decision:
        self._raw = bytes(_raw[:HEADER_BYTES])
        t = self.clock()
        if t - self._last_expire > 5:
            self.conntrack.expire(t)
            self._last_expire = t
        direction = direction or self.direction_of(pkt)
        self._direction = direction

        if self.cfg.whitelist and self._in(pkt.src_ip, self.cfg.whitelist):
            return self._finish(Decision("ACCEPT", "whitelisted source", pkt, stage="whitelist"))
        if self.cfg.blacklist and self._in(pkt.src_ip, self.cfg.blacklist):
            return self._finish(Decision("DROP", "blacklisted source", pkt, stage="blacklist"))
        banned = self.ids.is_blocked(pkt.src_ip, t)
        if banned:
            return self._finish(Decision("DROP", f"source banned by IDS: {banned}", pkt, stage="ids_ban"))
        if direction == "in":
            alert = self.ids.inspect(pkt, t)
            if alert:
                log.warning("IDS ALERT %s from %s - banned for %ss",
                            alert, pkt.src_ip, self.ids.block_seconds)
                return self._finish(Decision("DROP", f"IDS: {alert}", pkt, stage="ids", ids_alert=alert))

        state = NEW
        if self.cfg.stateful:
            state, flow = self.conntrack.lookup(pkt, t)
            if state == ESTABLISHED:
                self.conntrack.update(flow, pkt, t)
                return self._finish(Decision("ACCEPT", "established connection", pkt, state=state, stage="conntrack"))
            if state == INVALID and self.cfg.pickup_outbound and direction == "out" and not pkt.has_flag(RST):
                # A connection this host is already part of (opened before PyWall started):
                # judge it like a new one; if a rule allows it, it is tracked as established.
                # Inbound packets with no connection stay INVALID, so spoofing protection holds.
                state = NEW
            if state == INVALID and self.cfg.drop_invalid:
                return self._finish(Decision("DROP", "invalid state (no matching connection)", pkt, state=state, stage="conntrack"))

        decision = None
        for rule in self.cfg.rules:
            if rule.enabled and rule.matches(pkt, direction):
                rule.hits += 1
                if rule.action == "ACCEPT" and not rule.within_rate(pkt, t):
                    decision = Decision("DROP", f"rate limit exceeded ({rule.describe()})", pkt, rule, state, stage="rule", rate_limited=True)
                else:
                    decision = Decision(rule.action, rule.describe(), pkt, rule, state, stage="rule")
                break
        if decision is None:
            decision = Decision(self.cfg.default_policy, "default policy", pkt, state=state, stage="policy")

        if decision.verdict == "ACCEPT" and self.cfg.stateful and state == NEW:
            self.conntrack.track_new(pkt, t)
        return self._finish(decision)

    def _finish(self, d: Decision) -> Decision:
        if d.packet is not None:
            d.direction = d.direction or self._direction
            d.header = d.header or getattr(self, "_raw", b"")
        self.stats[d.verdict] += 1
        self.stats[f"reason:{d.reason}"] += 1
        level = logging.INFO if (d.verdict == "DROP" or (d.rule and d.rule.log)) else logging.DEBUG
        log.log(level, "%-6s %-55s %s", d.verdict,
                d.packet.summary() if d.packet else "<unparseable>", d.reason)
        for listener in self.listeners:
            try:
                listener(d)
            except Exception:           # an observer must never break filtering
                log.exception("decision listener failed")
        return d

    def report(self) -> str:
        lines = ["", paint("=== Firewall statistics ===", "bold"),
                 f"Accepted: {paint(str(self.stats['ACCEPT']), 'bold', 'green')}   "
                 f"Dropped: {paint(str(self.stats['DROP']), 'bold', 'red')}   "
                 f"Tracked connections: {len(self.conntrack)}"]
        lines.append(paint("Verdict reasons:", "bold"))
        for key, n in self.stats.most_common():
            if key.startswith("reason:"):
                lines.append(f"  {n:6d}  {key[7:]}")
        lines.append(paint("Rule hits:", "bold"))
        for r in self.cfg.rules:
            lines.append(f"  {r.hits:6d}  [{r.id}] {paint.verdict(r.action)} {r.describe()}")
        if self.ids.alerts:
            lines.append(paint("IDS alerts:", "bold"))
            for _, ip, reason in self.ids.alerts:
                lines.append(paint(f"  {ip}: {reason}", "yellow"))
        return "\n".join(lines)
