"""Dashboard server: standard library only.

    GET  /api/state            full snapshot (stats, rules, config, recent packets, events, series, flows)
    GET  /api/stream           Server-Sent Events: batched updates every 250 ms
    GET  /api/packets/<id>     one packet with its header dissection and pipeline explanation
    POST /api/explain          test a hypothetical packet against the pipeline (read-only)
    GET  /api/rules            the rule table
    POST /api/rules            create a rule            PUT    /api/rules/<id>  replace a rule
    POST /api/rules/order      reorder rules            DELETE /api/rules/<id>  delete a rule
    POST /api/rules/preview    "what if": replay recent traffic against a draft change (read-only)
    GET  /api/connections      the connection-tracking table
    PUT  /api/ids              change IDS thresholds    POST /api/bans, DELETE /api/bans/<ip>
    POST /api/attack           simulated source only: launch an attack now
    GET  /api/sessions         saved sessions           GET /api/export/report.md, /api/export/blocked.pcap
    GET  /*                    the built dashboard (firewall/web/)

Rule changes are validated with the same parser the firewall uses, swapped in
atomically under the engine lock, saved to the config file, and recorded as
configuration events. Bound to 127.0.0.1 by default; every request that changes
something must carry the header "X-PyWall: 1" (browsers will not send a custom
header cross-origin without a CORS preflight, which this server never grants).
"""

from __future__ import annotations

import ipaddress
import json
import mimetypes
import os
import queue
import re
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import export
from .analysis import analyse, preview
from .explain import explain
from .packet import PacketError, build_icmp, build_tcp, build_udp, dissect, is_v6, parse_packet
from .rules import RuleError, rule_from_dict

WEB_ROOT = Path(__file__).resolve().parent / "web"
FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}


class RuleStore:
    """Edits the live rule table and IDS settings and keeps the config file in step."""

    def __init__(self, fw, monitor, config_path: str | None):
        self.fw, self.monitor, self.path = fw, monitor, Path(config_path) if config_path else None

    def _save(self) -> None:
        if not self.path:
            return
        data = json.loads(self.path.read_text())
        data["rules"] = [r.spec for r in self.fw.cfg.rules]
        data["ids"] = self.fw.ids.settings()
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".rules-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        st = self.path.stat()
        os.chmod(tmp, st.st_mode & 0o777)
        if os.geteuid() == 0:                 # live mode runs as root: keep the file owned by its user
            os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, self.path)

    def _build(self, spec: dict, rule_id: int, position: int):
        spec = {k: v for k, v in spec.items() if v not in (None, "", []) and k not in ("hits", "position", "finding")}
        spec["id"] = rule_id
        rule = rule_from_dict(spec, position, self.fw.cfg.local_networks)   # raises RuleError with a readable message
        return rule

    # ------------------------------------------------------------- drafts
    def draft(self, op: str, spec: dict | None = None, rule_id: int | None = None,
              position: int | None = None, ids: list[int] | None = None) -> tuple[list, dict]:
        """The rule table as it would be after a change, without applying it.
        Returns (rules, info) where info describes the change for events."""
        rules = list(self.fw.cfg.rules)
        if op == "create":
            new_id = max((r.id for r in rules), default=0) + 1
            pos = len(rules) if position is None else max(0, min(len(rules), int(position) - 1))
            rule = self._build(spec or {}, new_id, pos + 1)
            rules.insert(pos, rule)
            return rules, {"id": new_id, "rule": rule, "position": pos + 1}
        if op == "update":
            idx = next((i for i, r in enumerate(rules) if r.id == rule_id), None)
            if idx is None:
                raise KeyError(rule_id)
            old = rules[idx]
            rule = self._build(spec or {}, rule_id, idx + 1)
            rule.hits = old.hits
            rules[idx] = rule
            return rules, {"id": rule_id, "rule": rule, "old": old}
        if op == "delete":
            gone = next((r for r in rules if r.id == rule_id), None)
            if gone is None:
                raise KeyError(rule_id)
            return [r for r in rules if r.id != rule_id], {"id": rule_id, "rule": gone}
        if op == "reorder":
            by_id = {r.id: r for r in rules}
            if sorted(ids or []) != sorted(by_id):
                raise RuleError("the new order must list every rule exactly once")
            return [by_id[i] for i in ids], {"order": ids}
        raise ValueError("op must be create, update, delete or reorder")

    def preview(self, body: dict) -> dict:
        with self.fw.lock:
            rules, _ = self.draft(body.get("op", ""), body.get("spec"), _int(body.get("id")),
                                  body.get("position"), [int(i) for i in body.get("ids") or []])
            with self.monitor.lock:
                records = list(self.monitor.packets)
            return preview(self.fw, records, rules)

    # ------------------------------------------------------------ changes
    def create(self, spec: dict, position: int | None = None) -> dict:
        with self.fw.lock:
            self.fw.cfg.rules, info = self.draft("create", spec, position=position)
            self._save()
            rule = info["rule"]
            self.monitor.event("config", "info", f"Rule {info['id']} created",
                               f"{rule.action} {rule.describe()}, at position {info['position']}")
        return {"id": info["id"]}

    def update(self, rule_id: int, spec: dict) -> dict:
        with self.fw.lock:
            self.fw.cfg.rules, info = self.draft("update", spec, rule_id)
            self._save()
            old, rule = info["old"], info["rule"]
            what = ("enabled" if rule.enabled else "disabled") if old.enabled != rule.enabled and \
                {k: v for k, v in old.spec.items() if k != "enabled"} == \
                {k: v for k, v in rule.spec.items() if k != "enabled"} else "edited"
            self.monitor.event("config", "info", f"Rule {rule_id} {what}", rule.describe())
        return {"id": rule_id}

    def delete(self, rule_id: int) -> dict:
        with self.fw.lock:
            self.fw.cfg.rules, info = self.draft("delete", rule_id=rule_id)
            self._save()
            self.monitor.event("config", "notice", f"Rule {rule_id} deleted", info["rule"].describe())
        return {"id": rule_id}

    def reorder(self, ids: list[int]) -> dict:
        with self.fw.lock:
            self.fw.cfg.rules, _ = self.draft("reorder", ids=ids)
            self._save()
            self.monitor.event("config", "info", "Rules reordered", "New order: " + ", ".join(map(str, ids)))
        return {"order": ids}

    # ---------------------------------------------------------------- IDS
    def set_ids(self, body: dict) -> dict:
        """Change IDS settings. Keys as in the config file; each threshold and window
        must be a positive number."""
        cfg: dict = {}
        if "enabled" in body:
            cfg["enabled"] = bool(body["enabled"])
        if "block_seconds" in body:
            cfg["block_seconds"] = _positive(body["block_seconds"], "ban length", 3600)
        for key, label in (("syn_flood", "SYN flood"), ("port_scan", "port scan"), ("icmp_flood", "ping flood")):
            if key in body:
                d = body[key] or {}
                cfg[key] = {"threshold": int(_positive(d.get("threshold"), f"{label} threshold", 100000)),
                            "window": _positive(d.get("window"), f"{label} window", 600)}
        with self.fw.lock:
            before = self.fw.ids.settings()
            self.fw.ids.configure(cfg)
            self._save()
            after = self.fw.ids.settings()
            changed = [k for k in after if after[k] != before[k]]
            if changed:
                self.monitor.event("config", "info", "Intrusion detection settings changed",
                                   "; ".join(_ids_text(k, after[k]) for k in changed))
        return {"ids": after}

    def ban(self, body: dict) -> dict:
        src = str(body.get("src", "")).strip()
        try:
            src = str(ipaddress.ip_address(src))
        except ValueError:
            raise ValueError(f"{src or 'an empty value'} is not an IP address") from None
        seconds = _positive(body.get("seconds", self.fw.ids.block_seconds), "ban length", 86400)
        reason = "banned by hand from the dashboard"
        with self.fw.lock:
            self.fw.ids.ban(src, self.fw.clock(), seconds, reason)
            with self.monitor.lock:
                self.monitor.note_ban(src, seconds)
                self.monitor.event("ids", "warning", "Source banned by hand", f"Every packet from it is dropped for {seconds:g} s.", src=src)
        return {"src": src, "seconds": seconds}

    def unban(self, src: str) -> dict:
        with self.fw.lock:
            if not self.fw.ids.unban(src):
                raise KeyError(src)
            with self.monitor.lock:
                self.monitor.note_unban(src)
                self.monitor.event("ids", "info", "Ban lifted by hand", "Traffic from it is judged normally again.", src=src)
        return {"src": src}


def _int(v):
    return None if v in (None, "") else int(v)


def _positive(v, label: str, limit: float) -> float:
    try:
        n = float(v)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a number") from None
    if not 0 < n <= limit:
        raise ValueError(f"{label} must be more than 0 and at most {limit:g}")
    return int(n) if n.is_integer() else n


def _ids_text(key: str, value) -> str:
    if key == "enabled":
        return "detection " + ("on" if value else "off")
    if key == "block_seconds":
        return f"ban length {value} s"
    return f"{key.replace('_', ' ')}: more than {value['threshold']} in {value['window']} s"


def packet_from_request(body: dict) -> bytes:
    proto = str(body.get("proto", "tcp")).lower()
    src, dst = str(body.get("src", "")).strip(), str(body.get("dst", "")).strip()
    for label, a in (("source", src), ("destination", dst)):
        try:
            ipaddress.ip_address(a)
        except ValueError:
            raise ValueError(f"{label} {a or '(empty)'} is not an IPv4 or IPv6 address") from None
    sport, dport = int(body.get("sport") or 0), int(body.get("dport") or 0)
    if proto == "tcp":
        flags = sum(FLAG_BITS[c] for c in str(body.get("flags", "S")).upper() if c in FLAG_BITS)
        return build_tcp(src, dst, sport, dport, flags)
    if proto == "udp":
        return build_udp(src, dst, sport, dport)
    if proto in ("icmp", "icmpv6"):
        t = int(body.get("icmpType", 8))
        if is_v6(src) and t in (0, 8):          # the form speaks IPv4 ping numbers; IPv6 uses 129/128
            t = {8: 128, 0: 129}[t]
        return build_icmp(src, dst, t)
    raise ValueError("protocol must be tcp, udp or icmp")


ATTACK_COOLDOWN = 2.0      # seconds between dashboard-launched attacks


def make_handler(fw, monitor, store: RuleStore, read_only: bool = False, generator=None):
    last_attack = [0.0]

    class Handler(BaseHTTPRequestHandler):
        server_version = "PyWall"
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):          # keep the console for firewall output
            pass

        # ----------------------------------------------------------- helpers
        def send_json(self, data, status=200):
            body = json.dumps(data, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def download(self, data: bytes, ctype: str, name: str):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def error(self, status, message):
            self.send_json({"error": message}, status)

        def body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 64_000:
                raise ValueError("request too large")
            return json.loads(self.rfile.read(length) or b"{}")

        def guarded(self) -> bool:
            if self.headers.get("X-PyWall") != "1" or "json" not in (self.headers.get("Content-Type") or ""):
                self.error(403, "missing X-PyWall header or JSON content type")
                return False
            return True

        # ------------------------------------------------------------- GET
        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/api/health":
                return self.send_json({"ok": True})
            if path == "/api/state":
                return self.send_json(monitor.snapshot())
            if path == "/api/rules":
                with fw.lock:
                    return self.send_json(monitor.rules())
            if path == "/api/flows":
                q = parse_qs(urlparse(self.path).query)
                window = max(10, min(900, int((q.get("window") or ["60"])[0])))
                with fw.lock, monitor.lock:
                    return self.send_json({"window": window, "flows": monitor.flows(window),
                                           "series": monitor.series(window)})
            if path == "/api/stream":
                return self.stream()
            if path == "/api/connections":
                q = parse_qs(urlparse(self.path).query)
                limit = max(1, min(2000, int((q.get("limit") or ["500"])[0])))
                with fw.lock:
                    return self.send_json(monitor.connections(limit))
            if path == "/api/sessions":
                return self.send_json({"sessions": monitor.history.sessions() if monitor.history else []})
            if path == "/api/export/report.md":
                snap = monitor.snapshot()
                with fw.lock:
                    findings = analyse(fw.cfg.rules)
                return self.download(export.report(snap, findings).encode(), "text/markdown; charset=utf-8",
                                     f"pywall-report-{time.strftime('%Y%m%d-%H%M%S')}.md")
            if path == "/api/export/blocked.pcap":
                with monitor.lock:
                    held = list(monitor.held)
                return self.download(export.pcap(held), "application/vnd.tcpdump.pcap",
                                     f"pywall-blocked-{time.strftime('%Y%m%d-%H%M%S')}.pcap")
            m = re.fullmatch(r"/api/packets/(\d+)", path)
            if m:
                return self.packet(int(m.group(1)))
            if path.startswith("/api/"):
                return self.error(404, "no such endpoint")
            return self.static(path)

        def packet(self, pid: int):
            with fw.lock, monitor.lock:
                rec = next((p for p in reversed(monitor.packets) if p["id"] == pid), None) \
                    or next((p for p in reversed(monitor.held) if p["id"] == pid), None)
                if rec is None:
                    return self.error(404, "packet no longer in the buffer")
                raw = bytes.fromhex(rec["header"])
                out = {"packet": rec, "layers": dissect(raw)}
                try:
                    out["explain"] = explain(fw, parse_packet(raw), rec["dir"])
                except PacketError:
                    out["explain"] = None
            self.send_json(out)

        def stream(self):
            q = monitor.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")      # reverse proxies must not hold the stream back
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                self.wfile.write(b"retry: 2000\n\n")
                self.wfile.flush()
                while True:
                    try:
                        msg = q.get(timeout=15)
                    except queue.Empty:
                        msg = ": keep-alive\n\n"
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                monitor.unsubscribe(q)
                self.close_connection = True

        def static(self, path: str):
            rel = path.lstrip("/") or "index.html"
            target = (WEB_ROOT / rel).resolve()
            if not str(target).startswith(str(WEB_ROOT)) or not target.is_file():
                target = WEB_ROOT / "index.html"          # single-page app routes
            if not target.is_file():
                return self.error(503, "dashboard not built: run `npm run build` in web/")
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache" if target.name == "index.html" else "max-age=31536000, immutable")
            self.end_headers()
            self.wfile.write(data)

        # ------------------------------------------------- POST/PUT/DELETE
        def mutate(self, fn):
            if not self.guarded():
                return
            if read_only:
                return self.error(403, "this is a read-only demo: rules can be inspected and tested, not changed")
            try:
                self.send_json(fn())
            except KeyError:
                self.error(404, "no such rule" if "rules" in self.path else "not found")
            except (RuleError, ValueError, OSError, PacketError) as exc:
                self.error(400, str(exc))

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/api/explain":
                if not self.guarded():
                    return
                try:
                    b = self.body()
                    pkt = parse_packet(packet_from_request(b))
                    with fw.lock:
                        result = explain(fw, pkt, b.get("dir") or None)
                    self.send_json(result)
                except (ValueError, OSError, PacketError) as exc:
                    self.error(400, str(exc))
                return
            if path == "/api/rules":
                def create():
                    b = self.body()
                    return store.create(b.get("spec", {}), b.get("position"))
                return self.mutate(create)
            if path == "/api/rules/order":
                return self.mutate(lambda: store.reorder([int(i) for i in self.body().get("ids", [])]))
            if path == "/api/rules/preview":        # read-only: allowed on the public demo too
                if not self.guarded():
                    return
                try:
                    return self.send_json(store.preview(self.body()))
                except KeyError:
                    return self.error(404, "no such rule")
                except (RuleError, ValueError, TypeError) as exc:
                    return self.error(400, str(exc))
            if path == "/api/attack":
                return self.attack()
            if path == "/api/bans":
                return self.mutate(lambda: store.ban(self.body()))
            self.error(404, "no such endpoint")

        def attack(self):
            """Simulated source only: start an attack now. Allowed on the read-only demo,
            since it changes no configuration, but limited to one every ATTACK_COOLDOWN s."""
            if not self.guarded():
                return
            if generator is None:
                return self.error(409, "attacks can only be launched on simulated traffic")
            wait = last_attack[0] + ATTACK_COOLDOWN - time.time()
            if wait > 0:
                return self.error(429, f"an attack was just launched; try again in {wait:.0f} s")
            try:
                result = generator.launch(str(self.body().get("kind", "")))
            except ValueError as exc:
                return self.error(400, str(exc))
            last_attack[0] = time.time()
            with monitor.lock:
                monitor.event("system", "info", "Attack launched from the dashboard",
                              f"Simulated {result['kind'].replace('_', ' ')} from {result['src']}: {result['what']}.",
                              src=result["src"])
            self.send_json(result)

        def do_PUT(self):
            if urlparse(self.path).path == "/api/ids":
                return self.mutate(lambda: store.set_ids(self.body()))
            m = re.fullmatch(r"/api/rules/(\d+)", urlparse(self.path).path)
            if not m:
                return self.error(404, "no such endpoint")
            self.mutate(lambda: store.update(int(m.group(1)), self.body().get("spec", {})))

        def do_DELETE(self):
            b = re.fullmatch(r"/api/bans/([0-9A-Fa-f.:]+)", urlparse(self.path).path)
            if b:
                return self.mutate(lambda: store.unban(b.group(1)))
            m = re.fullmatch(r"/api/rules/(\d+)", urlparse(self.path).path)
            if not m:
                return self.error(404, "no such endpoint")
            self.mutate(lambda: store.delete(int(m.group(1))))

    return Handler


def serve(fw, monitor, config_path: str | None, host: str = "127.0.0.1", port: int = 8080,
          read_only: bool = False, generator=None) -> ThreadingHTTPServer:
    store = RuleStore(fw, monitor, config_path)
    httpd = ThreadingHTTPServer((host, port), make_handler(fw, monitor, store, read_only, generator))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True, name="http").start()
    return httpd
