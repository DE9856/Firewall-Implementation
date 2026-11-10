"""Monitoring hub for the dashboard.

Subscribes to Firewall decisions and keeps, in memory for this session:
  * the most recent packets (ring buffer), each with its verdict and header bytes;
  * security events, derived only from real decisions and configuration changes
    (repeats of the same kind from the same source are coalesced into one event);
  * per-second counters (verdicts, direction, protocol, bytes, the stage that dropped);
  * flow aggregates (source -> path -> service/bin) for the overview map.

It never decides anything: it only observes. Subscribers (Server-Sent Events
clients) receive batched updates.
"""

from __future__ import annotations

import ipaddress
import json
import queue
import threading
import time
from collections import Counter, deque

from .engine import Decision
from .packet import PROTO_NAMES

SERVICES = {20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            80: "HTTP", 110: "POP3", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
            143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 1900: "SSDP", 3306: "MySQL",
            3389: "RDP", 5353: "mDNS", 8080: "HTTP alt"}
ICMP_NAMES = {0: "echo reply", 3: "unreachable", 8: "echo request", 11: "time exceeded"}
COALESCE_SECONDS = 10.0
HISTORY_SECONDS = 15 * 60


def service_of(p) -> str:
    """A label for what the packet is for: the well-known port it uses (either end), else the port."""
    if p.protocol == 1:
        return f"ICMP {ICMP_NAMES.get(p.icmp_type, p.icmp_type)}"
    for port in (p.dst_port, p.src_port):
        if port in SERVICES:
            return f"{SERVICES[port]} :{port}"
    return f"{PROTO_NAMES.get(p.protocol, p.protocol).upper()} :{p.dst_port}"


class Monitor:
    def __init__(self, fw, source: dict, max_packets: int = 5000, max_events: int = 1000):
        self.fw = fw
        self.source = source              # {"kind": "simulated"|"pcap"|"live", "label": ...}
        self.started = time.time()
        self.packets: deque = deque(maxlen=max_packets)
        self.events: deque = deque(maxlen=max_events)
        self.held: deque = deque(maxlen=1000)       # dropped packets, kept longer: they are rare and worth inspecting
        self.seconds: dict[int, Counter] = {}
        self.flow_window: deque = deque()          # (time, key, bytes) for the last 15 minutes
        self.seq = 0
        self.event_seq = 0
        self.totals = Counter()
        self._open: dict[tuple, dict] = {}         # coalescing: key -> event
        self._known_bans: dict[str, float] = {}
        self._pending_packets: list = []
        self._pending_events: dict[int, dict] = {}
        self.subscribers: list[queue.Queue] = []
        self.lock = threading.Lock()
        fw.listeners.append(self.on_decision)
        self.event("system", "info", "PyWall started", f"Traffic source: {source.get('label', source['kind'])}")
        threading.Thread(target=self._broadcast_loop, daemon=True).start()

    # ------------------------------------------------------------ recording
    def _local(self, ip: str) -> bool:
        nets = self.fw.cfg.local_networks
        return bool(nets) and any(ipaddress.ip_address(ip) in n for n in nets)

    def on_decision(self, d: Decision) -> None:
        with self.lock:
            self.seq += 1
            p = d.packet
            rec = {
                "id": self.seq, "t": round(d.time, 3), "verdict": d.verdict, "reason": d.reason,
                "stage": d.stage, "dir": d.direction, "state": d.state,
                "rule": d.rule.id if d.rule else None, "ruleName": d.rule.describe() if d.rule else None,
                "idsAlert": d.ids_alert, "rateLimited": d.rate_limited, "header": d.header.hex(),
            }
            if p is not None:
                rec.update({"src": p.src_ip, "dst": p.dst_ip, "sport": p.src_port, "dport": p.dst_port,
                            "proto": p.proto_name, "len": p.length, "ttl": p.ttl, "flags": p.flag_str,
                            "icmpType": p.icmp_type, "icmpCode": p.icmp_code, "service": service_of(p)})
            else:
                rec.update({"src": None, "dst": None, "proto": "?", "len": len(d.header), "service": "malformed"})
            self.packets.append(rec)
            if rec["verdict"] == "DROP":
                self.held.append(rec)
            self._pending_packets.append(rec)
            self._count(rec)
            self._derive_events(d, rec)

    def _count(self, rec: dict) -> None:
        sec = int(rec["t"])
        c = self.seconds.get(sec)
        if c is None:
            c = self.seconds[sec] = Counter()
            for old in [s for s in self.seconds if s < sec - HISTORY_SECONDS]:
                del self.seconds[old]
        v = rec["verdict"]
        c[v] += 1
        c["bytes"] += rec.get("len") or 0
        c[f"dir:{rec['dir']}"] += 1
        c[f"proto:{rec['proto']}"] += 1
        if v == "DROP":
            c[f"stage:{rec['stage']}"] += 1
        self.totals[v] += 1
        self.totals[f"stage:{rec['stage']}:{v}"] += 1
        self.totals["bytes"] += rec.get("len") or 0
        if rec.get("src"):
            key = (rec["src"], "local" if self._local(rec["src"]) else "external",
                   "fast" if rec["stage"] == "conntrack" and v == "ACCEPT" else "rules",
                   rec["service"], v, rec["stage"], rec["dir"], rec["proto"], rec["dst"], rec["rule"])
            self.flow_window.append((rec["t"], key, rec.get("len") or 0))
            while self.flow_window and self.flow_window[0][0] < rec["t"] - HISTORY_SECONDS:
                self.flow_window.popleft()

    # --------------------------------------------------------------- events
    def event(self, kind: str, severity: str, title: str, detail: str = "", src: str | None = None,
              packet: int | None = None, coalesce: tuple | None = None, t: float | None = None) -> dict:
        """Record an event. With `coalesce`, a repeat within COALESCE_SECONDS updates the
        open event's count instead of adding a new one."""
        t = t or time.time()
        if coalesce:
            ev = self._open.get(coalesce)
            if ev and t - ev["last"] <= COALESCE_SECONDS:
                ev["count"] += 1
                ev["last"] = round(t, 3)
                ev["packets"] = (ev["packets"] + [packet])[-20:] if packet else ev["packets"]
                self._pending_events[ev["id"]] = ev
                return ev
        self.event_seq += 1
        ev = {"id": self.event_seq, "kind": kind, "severity": severity, "title": title, "detail": detail,
              "src": src, "first": round(t, 3), "last": round(t, 3), "count": 1,
              "packets": [packet] if packet else []}
        self.events.append(ev)
        self._pending_events[ev["id"]] = ev
        if coalesce:
            self._open[coalesce] = ev
        return ev

    def _derive_events(self, d: Decision, rec: dict) -> None:
        src, pid, t = rec.get("src"), rec["id"], rec["t"]
        if d.ids_alert:
            until = self.fw.ids.blocked.get(src, (0, ""))[0]
            self.event("ids", "critical", f"{d.ids_alert.split(' (')[0].capitalize()} detected",
                       f"{d.ids_alert}. Source banned for {self.fw.ids.block_seconds} s.",
                       src=src, packet=pid, t=t)
            self._known_bans[src] = time.time() + max(0.0, until - self.fw.clock())
        elif d.stage == "ids_ban":
            self.event("ban", "warning", "Banned source still sending", d.reason.split(": ", 1)[-1],
                       src=src, packet=pid, coalesce=("ban", src), t=t)
        elif d.rate_limited:
            self.event("rate", "warning", "Rate limit exceeded", f"{d.reason}",
                       src=src, packet=pid, coalesce=("rate", src, rec["rule"]), t=t)
        elif d.stage == "conntrack" and d.verdict == "DROP":
            self.event("invalid", "notice", "Packet with no matching connection",
                       f"{rec['proto'].upper()} {rec.get('flags') or ''} packet that cannot open a connection",
                       src=src, packet=pid, coalesce=("invalid", src), t=t)
        elif d.stage == "parse":
            self.event("malformed", "notice", "Malformed packet dropped", d.reason, packet=pid,
                       coalesce=("malformed",), t=t)
        elif d.stage == "blacklist":
            self.event("blacklist", "notice", "Blacklisted source", "Dropped by the blacklist",
                       src=src, packet=pid, coalesce=("blacklist", src), t=t)
        elif d.stage == "rule" and d.rule and (d.rule.log or d.verdict == "DROP"):
            sev = "notice" if d.verdict == "DROP" else "info"
            self.event("rule", sev, f"Rule {d.rule.id} {'dropped' if d.verdict == 'DROP' else 'allowed'} traffic",
                       d.rule.describe(), src=src, packet=pid,
                       coalesce=("rule", d.rule.id, src, d.verdict), t=t)

    def _check_bans(self) -> None:
        now = time.time()
        for ip, until in list(self._known_bans.items()):
            if now >= until:
                del self._known_bans[ip]
                self.event("ids", "info", "Ban lifted", "The IDS ban expired; traffic is judged normally again.",
                           src=ip)

    # ------------------------------------------------------------- snapshots
    def stats(self) -> dict:
        now = time.time()
        recent = sum(self.seconds.get(int(now) - i, Counter())["ACCEPT"] +
                     self.seconds.get(int(now) - i, Counter())["DROP"] for i in range(1, 6))
        fw = self.fw
        return {
            "total": self.totals["ACCEPT"] + self.totals["DROP"],
            "accepted": self.totals["ACCEPT"], "dropped": self.totals["DROP"],
            "bytes": self.totals["bytes"], "rate": round(recent / 5, 1),
            "connections": len(fw.conntrack),
            "bans": sum(1 for _, (until, _r) in fw.ids.blocked.items() if until > fw.clock()),
            "rules": sum(1 for r in fw.cfg.rules if r.enabled), "rulesTotal": len(fw.cfg.rules),
            "byStage": {k.split(":")[1]: v for k, v in self.totals.items()
                        if k.startswith("stage:") and k.endswith(":DROP")},
            "fastPath": self.totals["stage:conntrack:ACCEPT"],
            "uptime": round(now - self.started),
        }

    def flows(self, window: int = 60) -> list[dict]:
        cutoff = time.time() - window
        agg: dict[tuple, list] = {}
        for t, key, size in self.flow_window:
            if t >= cutoff:
                a = agg.setdefault(key, [0, 0])
                a[0] += 1
                a[1] += size
        return [{"src": k[0], "group": k[1], "path": k[2], "service": k[3], "verdict": k[4],
                 "stage": k[5], "dir": k[6], "proto": k[7], "dst": k[8], "rule": k[9],
                 "count": c, "bytes": b} for k, (c, b) in agg.items()]

    def series(self, seconds: int = HISTORY_SECONDS) -> list[dict]:
        now = int(time.time())
        out = []
        for s in range(now - seconds, now + 1):
            c = self.seconds.get(s)
            if c:
                out.append({"t": s, **{k: v for k, v in c.items()}})
        return out

    def rules(self) -> list[dict]:
        out = []
        for pos, r in enumerate(self.fw.cfg.rules, start=1):
            out.append({"id": r.id, "position": pos, "hits": r.hits, "enabled": r.enabled, "spec": r.spec})
        return out

    def config(self) -> dict:
        cfg = self.fw.cfg
        return {"defaultPolicy": cfg.default_policy, "stateful": cfg.stateful, "dropInvalid": cfg.drop_invalid,
                "localNetworks": [str(n) for n in cfg.local_networks],
                "blacklist": [str(n) for n in cfg.blacklist], "whitelist": [str(n) for n in cfg.whitelist],
                "ids": {"enabled": self.fw.ids.enabled, "blockSeconds": self.fw.ids.block_seconds,
                        "synFlood": self.fw.ids.syn_cfg, "portScan": self.fw.ids.scan_cfg,
                        "icmpFlood": self.fw.ids.icmp_cfg},
                "bans": [{"src": ip, "reason": r, "remaining": round(until - self.fw.clock(), 1)}
                         for ip, (until, r) in self.fw.ids.blocked.items() if until > self.fw.clock()]}

    def snapshot(self) -> dict:
        with self.fw.lock, self.lock:
            return {"source": self.source, "started": self.started, "now": time.time(),
                    "stats": self.stats(), "config": self.config(), "rules": self.rules(),
                    "packets": list(self.packets)[-500:], "held": list(self.held), "events": list(self.events)[-300:],
                    "series": self.series(), "flows": self.flows()}

    # ------------------------------------------------------------ streaming
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self.lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q) -> None:
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def publish(self, kind: str, data) -> None:
        msg = f"event: {kind}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"
        for q in list(self.subscribers):
            try:
                q.put_nowait(msg)
            except queue.Full:           # a stalled client: drop it rather than block
                self.unsubscribe(q)

    def _broadcast_loop(self) -> None:
        tick = 0
        while True:
            time.sleep(0.25)
            tick += 1
            with self.fw.lock, self.lock:
                self._check_bans()
                packets, self._pending_packets = self._pending_packets, []
                events, self._pending_events = list(self._pending_events.values()), {}
                payload = {"now": time.time(), "packets": packets[-400:], "dropped": max(0, len(packets) - 400),
                           "events": events, "stats": self.stats()}
                if tick % 4 == 0:
                    payload["flows"] = self.flows()
                    payload["series"] = self.series(5)
                    payload["config"] = self.config()
                    payload["rules"] = [{"id": r.id, "hits": r.hits} for r in self.fw.cfg.rules]
            self.publish("update", payload)
