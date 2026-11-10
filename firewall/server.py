"""Dashboard server: standard library only.

    GET  /api/state            full snapshot (stats, rules, config, recent packets, events, series, flows)
    GET  /api/stream           Server-Sent Events: batched updates every 250 ms
    GET  /api/packets/<id>     one packet with its header dissection and pipeline explanation
    POST /api/explain          test a hypothetical packet against the pipeline (read-only)
    GET  /api/rules            the rule table
    POST /api/rules            create a rule            PUT    /api/rules/<id>  replace a rule
    POST /api/rules/order      reorder rules            DELETE /api/rules/<id>  delete a rule
    GET  /*                    the built dashboard (firewall/web/)

Rule changes are validated with the same parser the firewall uses, swapped in
atomically under the engine lock, saved to the config file, and recorded as
configuration events. Bound to 127.0.0.1 by default; every request that changes
something must carry the header "X-PyWall: 1" (browsers will not send a custom
header cross-origin without a CORS preflight, which this server never grants).
"""

from __future__ import annotations

import json
import mimetypes
import os
import queue
import re
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .explain import explain
from .packet import PacketError, build_icmp, build_tcp, build_udp, dissect, parse_packet
from .rules import RuleError, rule_from_dict

WEB_ROOT = Path(__file__).resolve().parent / "web"
FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}


class RuleStore:
    """Edits the live rule table and keeps the config file in step."""

    def __init__(self, fw, monitor, config_path: str | None):
        self.fw, self.monitor, self.path = fw, monitor, Path(config_path) if config_path else None

    def _save(self) -> None:
        if not self.path:
            return
        data = json.loads(self.path.read_text())
        data["rules"] = [r.spec for r in self.fw.cfg.rules]
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
        spec = {k: v for k, v in spec.items() if v not in (None, "", []) and k not in ("hits", "position")}
        spec["id"] = rule_id
        rule = rule_from_dict(spec, position, self.fw.cfg.local_networks)   # raises RuleError with a readable message
        return rule

    def create(self, spec: dict, position: int | None = None) -> dict:
        with self.fw.lock:
            rules = list(self.fw.cfg.rules)
            new_id = max((r.id for r in rules), default=0) + 1
            pos = len(rules) if position is None else max(0, min(len(rules), position - 1))
            rule = self._build(spec, new_id, pos + 1)
            rules.insert(pos, rule)
            self.fw.cfg.rules = rules
            self._save()
            self.monitor.event("config", "info", f"Rule {new_id} created",
                               f"{rule.action} {rule.describe()}, at position {pos + 1}")
        return {"id": new_id}

    def update(self, rule_id: int, spec: dict) -> dict:
        with self.fw.lock:
            rules = list(self.fw.cfg.rules)
            idx = next((i for i, r in enumerate(rules) if r.id == rule_id), None)
            if idx is None:
                raise KeyError(rule_id)
            old = rules[idx]
            rule = self._build(spec, rule_id, idx + 1)
            rule.hits = old.hits
            rules[idx] = rule
            self.fw.cfg.rules = rules
            self._save()
            what = ("enabled" if rule.enabled else "disabled") if old.enabled != rule.enabled and \
                {k: v for k, v in old.spec.items() if k != "enabled"} == \
                {k: v for k, v in rule.spec.items() if k != "enabled"} else "edited"
            self.monitor.event("config", "info", f"Rule {rule_id} {what}", rule.describe())
        return {"id": rule_id}

    def delete(self, rule_id: int) -> dict:
        with self.fw.lock:
            rules = [r for r in self.fw.cfg.rules if r.id != rule_id]
            if len(rules) == len(self.fw.cfg.rules):
                raise KeyError(rule_id)
            gone = next(r for r in self.fw.cfg.rules if r.id == rule_id)
            self.fw.cfg.rules = rules
            self._save()
            self.monitor.event("config", "notice", f"Rule {rule_id} deleted", gone.describe())
        return {"id": rule_id}

    def reorder(self, ids: list[int]) -> dict:
        with self.fw.lock:
            by_id = {r.id: r for r in self.fw.cfg.rules}
            if sorted(ids) != sorted(by_id):
                raise RuleError("the new order must list every rule exactly once")
            self.fw.cfg.rules = [by_id[i] for i in ids]
            self._save()
            self.monitor.event("config", "info", "Rules reordered", "New order: " + ", ".join(map(str, ids)))
        return {"order": ids}


def packet_from_request(body: dict) -> bytes:
    proto = str(body.get("proto", "tcp")).lower()
    src, dst = body.get("src", ""), body.get("dst", "")
    sport, dport = int(body.get("sport") or 0), int(body.get("dport") or 0)
    if proto == "tcp":
        flags = sum(FLAG_BITS[c] for c in str(body.get("flags", "S")).upper() if c in FLAG_BITS)
        return build_tcp(src, dst, sport, dport, flags)
    if proto == "udp":
        return build_udp(src, dst, sport, dport)
    if proto == "icmp":
        return build_icmp(src, dst, int(body.get("icmpType", 8)))
    raise ValueError("protocol must be tcp, udp or icmp")


def make_handler(fw, monitor, store: RuleStore, read_only: bool = False):
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
                self.error(404, "no such rule")
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
            self.error(404, "no such endpoint")

        def do_PUT(self):
            m = re.fullmatch(r"/api/rules/(\d+)", urlparse(self.path).path)
            if not m:
                return self.error(404, "no such endpoint")
            self.mutate(lambda: store.update(int(m.group(1)), self.body().get("spec", {})))

        def do_DELETE(self):
            m = re.fullmatch(r"/api/rules/(\d+)", urlparse(self.path).path)
            if not m:
                return self.error(404, "no such endpoint")
            self.mutate(lambda: store.delete(int(m.group(1))))

    return Handler


def serve(fw, monitor, config_path: str | None, host: str = "127.0.0.1", port: int = 8080,
          read_only: bool = False) -> ThreadingHTTPServer:
    store = RuleStore(fw, monitor, config_path)
    httpd = ThreadingHTTPServer((host, port), make_handler(fw, monitor, store, read_only))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True, name="http").start()
    return httpd
