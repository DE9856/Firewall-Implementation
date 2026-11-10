"""Static analysis of the rule table, and "what if" previews of rule changes.

Rules are checked top to bottom and the first match wins, so a rule placed
below a broader one can never decide anything. `analyse()` finds those rules:

  shadowed   - an earlier rule matches every packet this rule matches, with a
               different action: this rule never gets a say (usually a bug)
  redundant  - the same, but the earlier rule does the same thing: this rule
               can be removed without changing any verdict

Coverage is computed exactly for every condition PyWall supports (direction,
protocol, address blocks, port ranges, ICMP type, TCP flags); a rate limit on
the earlier rule does not matter, because a packet over the limit is still
decided by that rule (dropped) and never reaches the later one.

`preview()` replays recent real packets through the current and a draft rule
table and reports the verdicts that would change.
"""

from __future__ import annotations

from .packet import PacketError, parse_packet
from .rules import Rule, _FLAG_BITS

_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def _nets_cover(outer, inner) -> bool:
    """Every address in `inner` (None = any) is inside `outer` (None = any)."""
    if outer is None:
        return True
    if inner is None:
        return False
    return all(any(n.version == o.version and n.subnet_of(o) for o in outer) for n in inner)


def _ports_cover(outer, inner) -> bool:
    if outer is None:
        return True
    if inner is None:
        return False
    return all(any(olo <= lo and hi <= ohi for olo, ohi in outer) for lo, hi in inner)


def _flag_sets(spec: str | None) -> tuple[int, int]:
    must, _, must_not = (spec or "").upper().partition("!")
    return (sum(_FLAG_BITS[c] for c in must if c in _FLAG_BITS),
            sum(_FLAG_BITS[c] for c in must_not if c in _FLAG_BITS))


def covers(a: Rule, b: Rule) -> bool:
    """True when every packet that matches `b` also matches `a`."""
    if a.direction != "any" and a.direction != b.direction:
        return False
    if a.protocol is not None and a.protocol != b.protocol:
        return False
    if not (_nets_cover(a.src, b.src) and _nets_cover(a.dst, b.dst)):
        return False
    if not (_ports_cover(a.src_port, b.src_port) and _ports_cover(a.dst_port, b.dst_port)):
        return False
    if a.icmp_type is not None and a.icmp_type != b.icmp_type:
        return False
    if a.tcp_flags:
        a_must, a_not = _flag_sets(a.tcp_flags)
        b_must, b_not = _flag_sets(b.tcp_flags)
        # b's packets have every bit of b_must set and every bit of b_not clear;
        # a matches them all only if a's requirements are implied by b's
        if a_must & ~b_must or a_not & ~b_not:
            return False
    return True


def _empty(r: Rule) -> bool:
    """A rule that cannot match anything at all (contradictory flags)."""
    must, must_not = _flag_sets(r.tcp_flags)
    return bool(must & must_not)


def analyse(rules: list[Rule]) -> dict[int, dict]:
    """{rule id: finding} for every enabled rule that can never decide a packet."""
    out: dict[int, dict] = {}
    for j, b in enumerate(rules):
        if not b.enabled:
            continue
        if _empty(b):
            out[b.id] = {"kind": "never", "by": None,
                         "message": f"Its TCP flags condition ({b.tcp_flags}) requires a flag both set and clear, "
                                    "so no packet can match it."}
            continue
        for a in rules[:j]:
            if not a.enabled or not covers(a, b):
                continue
            same = a.action == b.action
            out[b.id] = {
                "kind": "redundant" if same else "shadowed", "by": a.id,
                "message": (f"Rule {a.id} ({a.describe()}) above it already matches every packet this rule "
                            f"matches and also {_verb(a.action)} them. Removing this rule changes nothing.")
                if same else
                (f"Rule {a.id} ({a.describe()}) above it matches every packet this rule matches and "
                 f"{_verb(a.action)} them first, so this rule never decides anything. "
                 f"Move it above rule {a.id} if it should win."),
            }
            break
    return out


def _verb(action: str) -> str:
    return {"ACCEPT": "allows", "DROP": "drops", "REJECT": "rejects"}[action]


def _first(rules: list[Rule], pkt, direction: str) -> tuple[str, Rule | None]:
    for r in rules:
        if r.enabled and r.matches(pkt, direction):
            return r.action, r
    return "", None


def preview(fw, records: list[dict], draft: list[Rule], limit_groups: int = 40) -> dict:
    """Replay recorded packets that reached the rule table through the current and the
    draft rule table. Only first-match decisions are compared: rate limits, the IDS and
    connection tracking are left out (a changed verdict for a connection's first packet
    would also change its replies, which this does not follow)."""
    cfg = fw.cfg
    checked = 0
    groups: dict[tuple, dict] = {}
    span = [None, None]
    for rec in records:
        if rec.get("stage") not in ("rule", "policy") or not rec.get("header"):
            continue
        try:
            pkt = parse_packet(bytes.fromhex(rec["header"]))
        except (PacketError, ValueError):
            continue
        checked += 1
        span[0] = rec["t"] if span[0] is None else min(span[0], rec["t"])
        span[1] = rec["t"] if span[1] is None else max(span[1], rec["t"])
        old_action, old_rule = _first(cfg.rules, pkt, rec["dir"])
        new_action, new_rule = _first(draft, pkt, rec["dir"])
        old_v = _verdict(old_action or cfg.default_policy)
        new_v = _verdict(new_action or cfg.default_policy)
        old_by = old_rule.id if old_rule else None
        new_by = new_rule.id if new_rule else None
        if (old_v, old_by) == (new_v, new_by) and old_action == new_action:
            continue
        port = pkt.dst_port if pkt.dst_port is not None else pkt.icmp_type
        key = (pkt.src_ip, rec["dir"], _PROTO.get(pkt.protocol, str(pkt.protocol)), port, old_v, new_v, old_by, new_by,
               old_action or "policy", new_action or "policy")
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"src": pkt.src_ip, "dir": rec["dir"], "proto": key[2], "port": port,
                               "service": rec.get("service"), "before": old_v, "after": new_v,
                               "beforeBy": old_by, "afterBy": new_by,
                               "beforeAction": key[8], "afterAction": key[9], "count": 0, "packets": []}
        g["count"] += 1
        if len(g["packets"]) < 5:
            g["packets"].append(rec["id"])
    changes = sorted(groups.values(), key=lambda g: -g["count"])
    flips = [g for g in changes if g["before"] != g["after"]]
    return {
        "checked": checked,
        "from": span[0], "to": span[1],
        "changed": sum(g["count"] for g in changes),
        "nowBlocked": sum(g["count"] for g in flips if g["after"] == "DROP"),
        "nowAllowed": sum(g["count"] for g in flips if g["after"] == "ACCEPT"),
        "otherRule": sum(g["count"] for g in changes if g["before"] == g["after"]),
        "groups": changes[:limit_groups],
        "moreGroups": max(0, len(changes) - limit_groups),
        "findings": {str(k): v for k, v in analyse(draft).items()},
    }


def _verdict(action: str) -> str:
    return "ACCEPT" if action == "ACCEPT" else "DROP"
