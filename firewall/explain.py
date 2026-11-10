"""Read-only explanation of how the pipeline treats a packet.

`explain()` walks the same stages as Firewall.decide() and reports what each
one would conclude, without changing any state: no hit counters, no rate-limit
tokens, no IDS counters, no connection-table entries. It powers the
dashboard's "why" panels and the rule tester.
"""

from __future__ import annotations

import ipaddress

from .conntrack import INVALID
from .packet import RST, Packet, reject_reply


def _in(ip: str, nets) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in nets)


def explain(fw, pkt: Packet, direction: str | None = None) -> dict:
    """Return {"direction", "stages": [...], "rules": [...], "verdict", "stage"}."""
    cfg = fw.cfg
    t = fw.clock()
    direction = direction or fw.direction_of(pkt)
    stages, decided = [], None

    def stage(name, outcome, detail, verdict=None):
        nonlocal decided
        stages.append({"stage": name, "outcome": outcome, "detail": detail,
                       "verdict": verdict if decided is None else None})
        if verdict and decided is None:
            decided = (name, verdict, detail)

    stage("parse", "pass", f"IPv{pkt.version} {pkt.proto_name.upper()} packet, {pkt.length} bytes")
    if cfg.whitelist and _in(pkt.src_ip, cfg.whitelist):
        stage("whitelist", "match", f"{pkt.src_ip} is whitelisted", "ACCEPT")
    else:
        stage("whitelist", "pass", "source not on the whitelist")
    if decided is None:
        if cfg.blacklist and _in(pkt.src_ip, cfg.blacklist):
            stage("blacklist", "match", f"{pkt.src_ip} is blacklisted", "DROP")
        else:
            stage("blacklist", "pass", "source not on the blacklist")
    if decided is None:
        entry = fw.ids.blocked.get(pkt.src_ip)
        if entry and t < entry[0]:
            stage("ids_ban", "match", f"source banned for {entry[0] - t:.0f} s more: {entry[1]}", "DROP")
        else:
            stage("ids_ban", "pass", "source not banned")
    if decided is None:
        stage("ids", "skipped" if direction == "in" else "pass",
              "rate detectors count live traffic only; not re-run for an explanation"
              if direction == "in" else "outbound traffic is not inspected by the IDS")
    rules_out = []
    if decided is None and cfg.stateful:
        state, flow = fw.conntrack.peek(pkt, t)
        if flow:
            stage("conntrack", "match", f"part of a tracked connection ({flow.state})", "ACCEPT")
        elif state == INVALID and cfg.pickup_outbound and direction == "out" and not pkt.has_flag(RST):
            stage("conntrack", "pass", "outbound packet of a connection opened before PyWall started: judged as NEW")
        elif state == INVALID and cfg.drop_invalid:
            stage("conntrack", "match", "cannot open a connection and none exists (INVALID)", "DROP")
        else:
            stage("conntrack", "pass", "NEW connection, goes to the rule table")
    if decided is None:
        for rule in cfg.rules:
            conds = rule.conditions(pkt, direction)
            ok = rule.enabled and all(c["ok"] for c in conds)
            rules_out.append({"id": rule.id, "name": rule.describe(), "action": rule.action,
                              "enabled": rule.enabled, "matched": ok, "conditions": conds})
            if ok:
                if rule.action == "REJECT":
                    reply = reject_reply(pkt, b"")
                    reject = reply[1] if reply else None
                    stage("rule", "match", f"rule {rule.id} ({rule.describe()}) matched first: rejected"
                          + (f", the sender gets a {reject}" if reject else " (no reply: errors are never answered)"), "DROP")
                else:
                    stage("rule", "match", f"rule {rule.id} ({rule.describe()}) matched first", rule.action)
                break
        else:
            stage("rule", "pass", "no rule matched")
    if decided is None:
        stage("policy", "match", f"default policy {cfg.default_policy}", cfg.default_policy)
    name, verdict, detail = decided
    return {"direction": direction, "stages": stages, "rules": rules_out,
            "verdict": verdict, "stage": name, "detail": detail}
