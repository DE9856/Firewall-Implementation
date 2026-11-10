#!/usr/bin/env python3
"""Check a live PyWall run from the outside (no root needed).

Start PyWall live first, in another terminal:
    sudo .venv/bin/python pywall.py serve --source live -i auto --lan auto [--dry-run]
then run:
    python3 demo/check_live.py

It makes real traffic from this machine and confirms, through the dashboard API,
that PyWall saw each packet and gave the verdict the rule set says it should:
  * HTTPS to example.com: outbound SYN allowed by rule 3, replies on the fast path
  * DNS query to 1.1.1.1: allowed out, reply accepted as established
  * ping 1.1.1.1: echo requests allowed out, echo replies accepted as established
  * TCP to example.com port 23 (Telnet): held by the "block outbound telnet" rule
  * the dashboard's live stream delivers updates
Nothing here changes the firewall; it only sends ordinary traffic and reads the API.
"""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

API = "http://127.0.0.1:8080"
GREEN, RED, YELLOW, GREY, BOLD, END = "\033[32m", "\033[31m", "\033[33m", "\033[90m", "\033[1m", "\033[0m"


def state():
    with urllib.request.urlopen(f"{API}/api/state", timeout=5) as r:
        return json.loads(r.read())


def report(ok, what, detail=""):
    mark = f"{GREEN}pass{END}" if ok else f"{RED}FAIL{END}" if ok is False else f"{YELLOW}info{END}"
    print(f"  {mark}  {what}" + (f"  {GREY}{detail}{END}" if detail else ""))
    return ok is not False


def main() -> int:
    try:
        s0 = state()
    except OSError as exc:
        print(f"{RED}Can't reach the dashboard at {API}: {exc}{END}\nStart PyWall live first (see the top of this file).")
        return 2
    src = s0["source"]
    print(f"{BOLD}PyWall live check{END}  {GREY}{src['label']}{END}")
    if src["kind"] != "live":
        print(f"{RED}The running dashboard is not in live mode ({src['kind']}).{END}")
        return 2
    dry = src.get("dryRun", False)
    start_id = s0["packets"][-1]["id"] if s0["packets"] else 0
    total0 = s0["stats"]["total"]

    # ---- make real traffic ----
    web = socket.gethostbyname("example.com")
    print(f"  {GREY}example.com is {web}; sending traffic...{END}")
    https_ok = telnet_result = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((web, 443), timeout=6) as raw, ctx.wrap_socket(raw, server_hostname="example.com") as tls:
            tls.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            https_ok = tls.recv(64).startswith(b"HTTP/")
    except OSError as exc:
        https_ok = f"error: {exc}"
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    dns_ok = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        u.settimeout(4)
        try:
            u.sendto(q, ("1.1.1.1", 53))
            dns_ok = len(u.recv(512)) > 12
        except OSError as exc:
            dns_ok = f"error: {exc}"
    ping = subprocess.run(["ping", "-c", "3", "-i", "0.3", "-W", "2", "1.1.1.1"], capture_output=True, text=True)
    t = time.time()
    try:
        with socket.create_connection((web, 23), timeout=4):
            telnet_result = "connected"
    except socket.timeout:
        telnet_result = "timed out"
    except OSError as exc:
        telnet_result = f"{exc.strerror or exc}"
    telnet_secs = time.time() - t
    time.sleep(1.5)

    # ---- read what PyWall saw ----
    s1 = state()
    pk = [p for p in s1["packets"] if p["id"] > start_id] + [p for p in s1.get("held", []) if p["id"] > start_id]
    seen = {p["id"]: p for p in pk}.values()

    def find(**kw):
        return [p for p in seen if all(p.get(k) == v for k, v in kw.items())]

    print(f"\n{BOLD}What PyWall decided{END}")
    ok = True
    syn = [p for p in find(dst=web, dport=443, dir="out") if "S" in (p.get("flags") or "") and "A" not in (p.get("flags") or "")]
    ok &= report(bool(syn) and syn[0]["verdict"] == "ACCEPT",
                 "HTTPS: outbound SYN allowed", f"{syn[0]['reason']}, rule {syn[0]['rule']}" if syn else "no SYN to :443 seen")
    replies = find(src=web, sport=443, dir="in")
    fast = [p for p in replies if p["stage"] == "conntrack" and p["verdict"] == "ACCEPT"]
    ok &= report(bool(fast) and len(fast) == len(replies),
                 "HTTPS: replies accepted on the fast path", f"{len(fast)} of {len(replies)} replies")
    ok &= report(https_ok is True, "HTTPS: page fetched end to end", "" if https_ok is True else str(https_ok))
    dns = find(dst="1.1.1.1", dport=53, dir="out")
    dns_in = find(src="1.1.1.1", sport=53, dir="in")
    ok &= report(bool(dns) and dns[0]["verdict"] == "ACCEPT" and all(p["verdict"] == "ACCEPT" for p in dns_in) and dns_ok is True,
                 "DNS: query out and answer back", f"{len(dns)} out, {len(dns_in)} in, resolver answered: {dns_ok}")
    echo = find(dst="1.1.1.1", proto="icmp", dir="out")
    reply = find(src="1.1.1.1", proto="icmp", dir="in")
    ok &= report(len(echo) >= 3 and all(p["verdict"] == "ACCEPT" for p in reply) and ping.returncode == 0,
                 "Ping: echo out, replies accepted", f"{len(echo)} requests, {len(reply)} replies, ping exit {ping.returncode}")
    tel = find(dst=web, dport=23, dir="out")
    held = [p for p in tel if p["verdict"] == "DROP"]
    ok &= report(bool(held) and held[0]["rule"] is not None,
                 "Telnet: held by the outbound Telnet rule",
                 f"{held[0]['reason']}, rule {held[0]['rule']}" if held else f"{len(tel)} packets seen")
    if dry:
        report(None, "dry run: the Telnet attempt was not really blocked", f"client saw: {telnet_result}")
    else:
        ok &= report(telnet_result == "timed out", "Telnet attempt really blocked (client timed out)",
                     f"client saw: {telnet_result} after {telnet_secs:.1f} s")

    # ---- live stream and overall health ----
    try:
        with urllib.request.urlopen(f"{API}/api/stream", timeout=5) as r:
            got = b""
            while b"event: update" not in got:
                got += r.read1(4096)
        ok &= report(True, "dashboard stream delivers live updates")
    except OSError as exc:
        ok &= report(False, "dashboard stream delivers live updates", str(exc))
    st = s1["stats"]
    report(None, "totals", f"{st['total'] - total0} packets during this check; {st['total']:,} since start, "
                           f"{st['dropped']:,} held, {st['connections']} connections, {st['rate']} pkt/s")
    stray = [p for p in seen if p["dir"] == "in" and p["stage"] == "conntrack" and p["verdict"] == "DROP"]
    report(None, "inbound packets with no connection (held)", f"{len(stray)} during the check")
    print(f"\n{GREEN + 'All checks passed.' if ok else RED + 'Some checks failed.'}{END}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
