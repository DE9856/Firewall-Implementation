"""Live enforcement on Linux through netfilter's NFQUEUE target.

The kernel hands each packet to this program and waits for a verdict:

    INPUT  chain --NFQUEUE 1--> Firewall.process(direction="in")  --> accept/drop
    OUTPUT chain --NFQUEUE 2--> Firewall.process(direction="out") --> accept/drop

Requires root and the `netfilterqueue` Python package.
"""

from __future__ import annotations

import logging
import shutil
import signal
import subprocess
import threading

from .engine import Firewall

log = logging.getLogger("firewall")

QUEUES = {"in": ("INPUT", 1), "out": ("OUTPUT", 2)}


def _iptables_rules(include_loopback: bool, interface: str | None = None):
    rules = []
    for direction, (chain, qnum) in QUEUES.items():
        spec = []
        flag = "-i" if chain == "INPUT" else "-o"
        if interface:
            spec += [flag, interface]           # only this interface is filtered
        elif not include_loopback:
            spec += ["!", flag, "lo"]
        # --queue-bypass: if this program is not running, traffic flows normally
        spec += ["-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"]
        rules.append((chain, spec))
    return rules


def _iptables(action: str, chain: str, spec: list[str]) -> None:
    subprocess.run(["iptables", action, chain, *spec], check=True)


def run_live(fw: Firewall, dry_run: bool = False, include_loopback: bool = False,
             interface: str | None = None) -> None:
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError as exc:
        raise SystemExit("netfilterqueue is not installed: pip install NetfilterQueue") from exc
    if shutil.which("iptables") is None:
        raise SystemExit("iptables command not found")

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
        for chain, spec in rules:
            _iptables("-I", chain, spec)
        log.info("Firewall active on %s%s. Press Ctrl+C to stop.", interface or "all interfaces",
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
        for chain, spec in rules:
            subprocess.run(["iptables", "-D", chain, *spec], check=False, stderr=subprocess.DEVNULL)
        # the queue threads are daemons and die with the process; unbinding while
        # they are blocked in recv() is unsafe, so we only remove the hooks
        log.info("iptables hooks removed.")
        print(fw.report())
