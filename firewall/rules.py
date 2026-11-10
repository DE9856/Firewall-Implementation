"""Rule model, matching logic and JSON loading."""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .packet import PROTO_NAMES, PROTO_NUMBERS, Packet

ACTIONS = ("ACCEPT", "DROP", "REJECT")   # REJECT = drop, and tell the sender (TCP RST / ICMP error)
POLICIES = ("ACCEPT", "DROP")
DIRECTIONS = ("in", "out", "any")


class RuleError(ValueError):
    """Raised for an invalid rule definition."""


LAN_TOKEN = "$LAN"       # in a rule's src/dst: the local networks of this machine


def _parse_net(value, lan=None):
    if value is None or value == "any":
        return None
    values = value if isinstance(value, list) else [value]
    out = []
    try:
        for v in values:
            if v == LAN_TOKEN:
                if not lan:
                    raise RuleError(f"{LAN_TOKEN} used but no local_networks are configured")
                out.extend(lan)
            else:
                out.append(ipaddress.ip_network(v, strict=False))
    except ValueError as exc:
        raise RuleError(str(exc)) from exc
    return out


def _parse_ports(value):
    """Accept 22, "8000-8100", [80, 443, "6000-6010"] -> list of (lo, hi)."""
    if value is None or value == "any":
        return None
    values = value if isinstance(value, list) else [value]
    ranges = []
    for v in values:
        if isinstance(v, int):
            lo = hi = v
        elif isinstance(v, str) and "-" in v:
            lo, hi = (int(x) for x in v.split("-", 1))
        else:
            lo = hi = int(v)
        if not (0 <= lo <= hi <= 65535):
            raise RuleError(f"invalid port range {v!r}")
        ranges.append((lo, hi))
    return ranges


def _parse_rate(value):
    """"10/s", "60/m" -> (tokens, per_seconds)."""
    if value is None:
        return None
    count, unit = str(value).split("/")
    per = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600}.get(unit)
    if per is None:
        raise RuleError(f"invalid rate unit in {value!r}")
    return int(count), per


class TokenBucket:
    """Classic token bucket: `rate` tokens are refilled every `per` seconds."""

    def __init__(self, rate: int, per: float, now: float):
        self.capacity = float(rate)
        self.tokens = float(rate)
        self.fill_rate = rate / per
        self.last = now

    def take(self, now: float) -> bool:
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.fill_rate)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


@dataclass
class Rule:
    id: int
    action: str
    name: str = ""
    direction: str = "any"
    protocol: int | None = None
    src: list | None = None
    dst: list | None = None
    src_port: list | None = None
    dst_port: list | None = None
    icmp_type: int | None = None
    tcp_flags: str | None = None   # e.g. "S" = SYN set; "S!A" = SYN set, ACK not set
    rate_limit: tuple | None = None
    log: bool = False
    enabled: bool = True
    hits: int = 0
    spec: dict = field(default_factory=dict, repr=False)   # the rule as written in JSON
    _buckets: dict = field(default_factory=dict, repr=False)

    # ---------------------------------------------------------------- matching
    def matches(self, pkt: Packet, direction: str) -> bool:
        if self.direction != "any" and self.direction != direction:
            return False
        if self.protocol is not None and pkt.protocol != self.protocol:
            return False
        if self.src and not _ip_in(pkt.src_ip, self.src):
            return False
        if self.dst and not _ip_in(pkt.dst_ip, self.dst):
            return False
        if self.src_port and not _port_in(pkt.src_port, self.src_port):
            return False
        if self.dst_port and not _port_in(pkt.dst_port, self.dst_port):
            return False
        if self.icmp_type is not None and pkt.icmp_type != self.icmp_type:
            return False
        if self.tcp_flags and not _flags_match(pkt, self.tcp_flags):
            return False
        return True

    def conditions(self, pkt: Packet, direction: str) -> list[dict]:
        """Each condition this rule checks, with the packet's value and whether it passed.
        Read-only: used to explain verdicts, never to decide them."""
        out = []

        def add(name, wanted, actual, ok):
            out.append({"field": name, "rule": wanted, "packet": actual, "ok": bool(ok)})
        if self.direction != "any":
            add("direction", self.direction, direction, self.direction == direction)
        if self.protocol is not None:
            add("protocol", PROTO_NAMES.get(self.protocol, str(self.protocol)),
                PROTO_NAMES.get(pkt.protocol, str(pkt.protocol)), pkt.protocol == self.protocol)
        if self.src:
            add("source", ", ".join(map(str, self.src)), pkt.src_ip, _ip_in(pkt.src_ip, self.src))
        if self.dst:
            add("destination", ", ".join(map(str, self.dst)), pkt.dst_ip, _ip_in(pkt.dst_ip, self.dst))
        if self.src_port:
            add("source port", _ports_str(self.src_port), pkt.src_port, _port_in(pkt.src_port, self.src_port))
        if self.dst_port:
            add("destination port", _ports_str(self.dst_port), pkt.dst_port, _port_in(pkt.dst_port, self.dst_port))
        if self.icmp_type is not None:
            add("ICMP type", self.icmp_type, pkt.icmp_type, pkt.icmp_type == self.icmp_type)
        if self.tcp_flags:
            add("TCP flags", self.tcp_flags, pkt.flag_str or "none", _flags_match(pkt, self.tcp_flags))
        return out

    def within_rate(self, pkt: Packet, now: float) -> bool:
        """Per-source rate limit. Returns False when the source is over its budget."""
        if not self.rate_limit:
            return True
        bucket = self._buckets.get(pkt.src_ip)
        if bucket is None:
            bucket = self._buckets[pkt.src_ip] = TokenBucket(*self.rate_limit, now=now)
        return bucket.take(now)

    def describe(self) -> str:
        return self.name or f"rule {self.id}"


def _ip_in(ip: str, nets) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in nets)


def _ports_str(ranges) -> str:
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)


def _port_in(port, ranges) -> bool:
    return port is not None and any(lo <= port <= hi for lo, hi in ranges)


_FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}


def _flags_match(pkt: Packet, spec: str) -> bool:
    must, _, must_not = spec.upper().partition("!")
    return (all(pkt.tcp_flags & _FLAG_BITS[c] for c in must)
            and not any(pkt.tcp_flags & _FLAG_BITS[c] for c in must_not))


def rule_from_dict(d: dict, index: int, lan=None) -> Rule:
    action = str(d.get("action", "")).upper()
    if action not in ACTIONS:
        raise RuleError(f"rule {index}: action must be one of {ACTIONS}")
    direction = d.get("direction", "any")
    if direction not in DIRECTIONS:
        raise RuleError(f"rule {index}: direction must be one of {DIRECTIONS}")
    proto = d.get("protocol")
    if proto in (None, "any"):
        proto_num = None
    elif str(proto).lower() in PROTO_NUMBERS:
        proto_num = PROTO_NUMBERS[str(proto).lower()]
    else:
        raise RuleError(f"rule {index}: unknown protocol {proto!r}")
    if (d.get("src_port") or d.get("dst_port")) and proto_num not in (6, 17):
        raise RuleError(f"rule {index}: ports require protocol tcp or udp")
    return Rule(
        id=d.get("id", index),
        action=action,
        name=d.get("name", ""),
        direction=direction,
        protocol=proto_num,
        src=_parse_net(d.get("src"), lan),
        dst=_parse_net(d.get("dst"), lan),
        src_port=_parse_ports(d.get("src_port")),
        dst_port=_parse_ports(d.get("dst_port")),
        icmp_type=d.get("icmp_type"),
        tcp_flags=d.get("tcp_flags"),
        rate_limit=_parse_rate(d.get("rate_limit")),
        log=bool(d.get("log", False)),
        enabled=bool(d.get("enabled", True)),
        spec={k: v for k, v in d.items() if not k.startswith("_")},
    )


@dataclass
class Config:
    default_policy: str = "DROP"
    stateful: bool = True
    drop_invalid: bool = True
    pickup_outbound: bool = True    # adopt connections already open when PyWall starts (see engine)
    local_networks: list = field(default_factory=list)
    blacklist: list = field(default_factory=list)
    whitelist: list = field(default_factory=list)
    ids: dict = field(default_factory=dict)
    rules: list = field(default_factory=list)


def load_config(path: str | Path, lan=None) -> Config:
    """Load a rule set. `lan` (a list of CIDR strings) replaces local_networks, e.g. the
    networks detected on the machine running a live demo; $LAN in rules follows it."""
    data = json.loads(Path(path).read_text())
    if lan:
        data["local_networks"] = lan
    return config_from_dict(data)


def config_from_dict(data: dict) -> Config:
    lan = _parse_net(data.get("local_networks")) or []
    policy = str(data.get("default_policy", "DROP")).upper()
    if policy not in POLICIES:
        raise RuleError("default_policy must be ACCEPT or DROP")
    rules = []
    for i, r in enumerate(data.get("rules", []), start=1):
        try:
            rules.append(rule_from_dict(r, i, lan))
        except (RuleError, ValueError) as exc:
            msg = str(exc)
            label = r.get("name") or f"#{i}" if isinstance(r, dict) else f"#{i}"
            raise RuleError(msg if msg.startswith(f"rule {i}") else f"rule {i} ({label}): {msg}") from exc
    return Config(
        default_policy=policy,
        stateful=bool(data.get("stateful", True)),
        drop_invalid=bool(data.get("drop_invalid", True)),
        local_networks=lan,
        pickup_outbound=bool(data.get("pickup_outbound", True)),
        blacklist=_parse_net(data.get("blacklist")) or [],
        whitelist=_parse_net(data.get("whitelist")) or [],
        ids=data.get("ids", {}),
        rules=rules,
    )


def now() -> float:
    return time.monotonic()
