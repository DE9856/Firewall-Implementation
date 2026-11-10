"""Lightweight intrusion detection: spots SYN floods, port scans and ICMP
floods per source address and bans the offender for a while."""

from __future__ import annotations

from collections import defaultdict, deque

from .packet import ACK, PROTO_TCP, SYN, Packet

DEFAULTS = {
    "enabled": True,
    "block_seconds": 60,
    "syn_flood": {"threshold": 20, "window": 1.0},
    "port_scan": {"threshold": 15, "window": 5.0},
    "icmp_flood": {"threshold": 10, "window": 1.0},
}


class SlidingCounter:
    """Counts events per key inside a sliding time window."""

    def __init__(self, window: float):
        self.window = window
        self.events: dict[str, deque] = defaultdict(deque)

    def add(self, key: str, now: float, value=None) -> deque:
        q = self.events[key]
        q.append((now, value))
        while q and now - q[0][0] > self.window:
            q.popleft()
        return q


class IntrusionDetector:
    def __init__(self, cfg: dict | None = None):
        cfg = {**DEFAULTS, **(cfg or {})}
        self.enabled = cfg["enabled"]
        self.block_seconds = cfg["block_seconds"]
        self.syn_cfg = {**DEFAULTS["syn_flood"], **cfg.get("syn_flood", {})}
        self.scan_cfg = {**DEFAULTS["port_scan"], **cfg.get("port_scan", {})}
        self.icmp_cfg = {**DEFAULTS["icmp_flood"], **cfg.get("icmp_flood", {})}
        self.syn = SlidingCounter(self.syn_cfg["window"])
        self.scan = SlidingCounter(self.scan_cfg["window"])
        self.icmp = SlidingCounter(self.icmp_cfg["window"])
        self.blocked: dict[str, tuple[float, str]] = {}   # ip -> (until, reason)
        self.alerts: list[tuple[float, str, str]] = []

    def configure(self, cfg: dict) -> None:
        """Apply new settings (same keys as the config file's "ids" section) at once.
        Counters and current bans are kept; a new window applies from the next packet."""
        if "enabled" in cfg:
            self.enabled = bool(cfg["enabled"])
        if "block_seconds" in cfg:
            self.block_seconds = cfg["block_seconds"]
        for key, attr, counter in (("syn_flood", "syn_cfg", self.syn), ("port_scan", "scan_cfg", self.scan),
                                   ("icmp_flood", "icmp_cfg", self.icmp)):
            if key in cfg:
                setattr(self, attr, {**getattr(self, attr), **cfg[key]})
                counter.window = getattr(self, attr)["window"]

    def settings(self) -> dict:
        """Current settings in the config file's shape."""
        return {"enabled": self.enabled, "block_seconds": self.block_seconds, "syn_flood": dict(self.syn_cfg),
                "port_scan": dict(self.scan_cfg), "icmp_flood": dict(self.icmp_cfg)}

    def ban(self, ip: str, now: float, seconds: float, reason: str) -> None:
        self.blocked[ip] = (now + seconds, reason)

    def unban(self, ip: str) -> bool:
        return self.blocked.pop(ip, None) is not None

    def is_blocked(self, ip: str, now: float) -> str | None:
        entry = self.blocked.get(ip)
        if not entry:
            return None
        until, reason = entry
        if now >= until:
            del self.blocked[ip]
            return None
        return reason

    def inspect(self, pkt: Packet, now: float) -> str | None:
        """Return an alert reason if this packet triggers a ban, else None."""
        if not self.enabled:
            return None
        src = pkt.src_ip
        reason = None
        if pkt.protocol == PROTO_TCP and pkt.has_flag(SYN) and not pkt.has_flag(ACK):
            q = self.syn.add(src, now)
            if len(q) > self.syn_cfg["threshold"]:
                reason = f"SYN flood ({len(q)} SYNs in {self.syn_cfg['window']}s)"
            ports = {v for _, v in self.scan.add(src, now, pkt.dst_port)}
            if reason is None and len(ports) > self.scan_cfg["threshold"]:
                reason = f"port scan ({len(ports)} ports in {self.scan_cfg['window']}s)"
        elif pkt.is_echo_request:
            q = self.icmp.add(src, now)
            if len(q) > self.icmp_cfg["threshold"]:
                reason = f"ICMP flood ({len(q)} pings in {self.icmp_cfg['window']}s)"
        if reason:
            self.blocked[src] = (now + self.block_seconds, reason)
            self.alerts.append((now, src, reason))
        return reason
