"""Live enforcement on Linux through netfilter's NFQUEUE target.

The kernel hands each packet to this program and waits for a verdict:

    INPUT  chain --NFQUEUE 1--> Firewall.process(direction="in")  --> accept/drop
    OUTPUT chain --NFQUEUE 2--> Firewall.process(direction="out") --> accept/drop

With ipv6=True the same hooks go into ip6tables (NFQUEUE numbers are shared
between address families, so one queue receives both).

A REJECT rule's reply (TCP RST or ICMP error) is written to a raw socket. It
carries the firewall mark REPLY_MARK, and the OUTPUT hook skips marked packets,
so PyWall never judges its own replies.

Requires root and the `netfilterqueue` Python package.
"""

from __future__ import annotations

import logging
import shutil
import socket
import signal
import subprocess
import threading

from .engine import Firewall

log = logging.getLogger("firewall")

QUEUES = {"in": ("INPUT", 1), "out": ("OUTPUT", 2)}
REPLY_MARK = 0x5057          # "PW": set on REJECT replies so they bypass the queue


def _iptables_rules(include_loopback: bool, interface: str | None = None):
    rules = []
    for direction, (chain, qnum) in QUEUES.items():
        spec = []
        flag = "-i" if chain == "INPUT" else "-o"
        if interface:
            spec += [flag, interface]           # only this interface is filtered
        elif not include_loopback:
            spec += ["!", flag, "lo"]
        if chain == "OUTPUT":
            spec += ["-m", "mark", "!", "--mark", hex(REPLY_MARK)]
        # --queue-bypass: if this program is not running, traffic flows normally
        spec += ["-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"]
        rules.append((chain, spec))
    return rules


def _iptables(action: str, chain: str, spec: list[str], tool: str = "iptables") -> None:
    subprocess.run([tool, action, chain, *spec], check=True)


def reply_sender():
    """A function that puts a REJECT reply (a full IP packet) on the wire."""
    socks = {}
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            sk = socket.socket(fam, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, REPLY_MARK)
            socks[fam] = sk
        except OSError as exc:
            log.warning("REJECT replies over %s are off: %s", "IPv6" if fam == socket.AF_INET6 else "IPv4", exc)

    def send(raw: bytes) -> None:
        if raw[0] >> 4 == 6 and socket.AF_INET6 in socks:
            socks[socket.AF_INET6].sendto(raw, (socket.inet_ntop(socket.AF_INET6, raw[24:40]), 0))
        elif raw[0] >> 4 == 4 and socket.AF_INET in socks:
            socks[socket.AF_INET].sendto(raw, (socket.inet_ntoa(raw[16:20]), 0))
    return send


def run_live(fw: Firewall, dry_run: bool = False, include_loopback: bool = False,
             interface: str | None = None, ipv6: bool = False) -> None:
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError as exc:
        raise SystemExit("netfilterqueue is not installed: pip install NetfilterQueue") from exc
    tools = ["iptables"] + (["ip6tables"] if ipv6 else [])
    for tool in tools:
        if shutil.which(tool) is None:
            raise SystemExit(f"{tool} command not found")
    if not dry_run:                  # a dry run drops nothing, so it rejects nothing either
        fw.reply_sender = reply_sender()

    def make_callback(direction):
        def callback(nfpkt):
            with fw.lock:
                decision = fw.process(nfpkt.get_payload(), direction)
            if decision.verdict == "ACCEPT" or dry_run:
                nfpkt.accept()
            else:
                nfpkt.drop()
        return callback

    rules = _iptables_rules(include_loopback, interface)
    queues = []
    try:
        for direction, (_chain, qnum) in QUEUES.items():
            q = NetfilterQueue()
            # Copy only the first 128 bytes of each packet to Python (headers are all PyWall
            # reads; the kernel still forwards the whole packet) and allow a deep queue, so
            # bursts on a real network are buffered instead of dropped by the kernel.
            q.bind(qnum, make_callback(direction), max_len=8192, range=128, sock_len=8 * 1024 * 1024)
            queues.append(q)
        for tool in tools:
            for chain, spec in rules:
                _iptables("-I", chain, spec, tool)
        log.info("Firewall active on %s (%s)%s. Press Ctrl+C to stop.", interface or "all interfaces",
                 "IPv4 and IPv6" if ipv6 else "IPv4",
                 " (DRY RUN - nothing is dropped)" if dry_run else "")
        threads = [threading.Thread(target=q.run, daemon=True) for q in queues]
        for t in threads:
            t.start()
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        try:
            while not stop.wait(1):
                pass
        except KeyboardInterrupt:
            pass
    finally:
        for tool in tools:
            for chain, spec in rules:
                subprocess.run([tool, "-D", chain, *spec], check=False, stderr=subprocess.DEVNULL)
        # the queue threads are daemons and die with the process; unbinding while
        # they are blocked in recv() is unsafe, so we only remove the hooks
        log.info("iptables hooks removed.")
        print(fw.report())
