#!/usr/bin/env python3
"""Live demo of PyWall filtering REAL packets (needs root).

    sudo .venv/bin/python demo/live_demo.py

What it does
  1. Builds a private test network: a network namespace "pywall-atk" (the
     attacker, 10.99.0.2 and 10.99.0.3) joined to this machine (10.99.0.1)
     by a veth cable. Your normal network and internet traffic is untouched:
     PyWall is attached ONLY to the veth interface "pw-host".
  2. Starts small TCP services on both ends and probes them with the
     firewall off (baseline).
  3. Starts PyWall in live mode (NFQUEUE) and repeats the probes, then runs
     real attacks: a spoofed TCP packet, a ping burst, a port scan and a
     SYN flood. Every verdict comes from PyWall's live log.
  4. Stops PyWall, checks the iptables hooks are gone and removes the test
     network.

Output: demo/live_session.json (used by `record_demo.py --live` to make the
video), demo/live_firewall.log (PyWall's own log). Everything is cleaned up
even if a step fails.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
NS, HOST_IF, ATK_IF = "pywall-atk", "pw-host", "pw-atk"
HOST_IP, ATK_IP, ATK2_IP = "10.99.0.1", "10.99.0.2", "10.99.0.3"
LOG = ROOT / "demo" / "live_firewall.log"
FW_OUT = ROOT / "demo" / "live_firewall_stdout.txt"
SESSION = ROOT / "demo" / "live_session.json"

sections: list[dict] = []
procs: list[subprocess.Popen] = []
fw_proc: subprocess.Popen | None = None
log_pos = 0
firewalld_added = False


# ----------------------------------------------------------------- helpers
def sh(cmd: list[str], check=True, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=True, **kw)


def in_ns(cmd: list[str]) -> list[str]:
    return ["ip", "netns", "exec", NS, *cmd]


def section(title: str) -> None:
    sections.append({"title": title, "items": []})
    print(f"\n\033[1;33m== {title}\033[0m")


def say(text: str) -> None:
    sections[-1]["items"].append({"type": "say", "text": text})
    print(f"\033[35m# {text}\033[0m")


def new_log_lines() -> list[str]:
    """Firewall log lines written since the last call, tidied for display."""
    global log_pos
    time.sleep(0.6)
    if not LOG.exists():
        return []
    with open(LOG) as f:
        f.seek(log_pos)
        raw = f.read()
        log_pos = f.tell()
    lines, established = [], 0
    for line in raw.splitlines():
        m = re.match(r"^(\S+) (\w+)\s+(.*)$", line)
        if not m:
            continue
        ts, _level, msg = m.groups()
        if msg.rstrip().endswith("established connection"):
            established += 1
            continue
        lines.append(f"{ts}  {re.sub(r'  +', '  ', msg)}")
    if established:
        lines.append(f"(+ {established} packets accepted as part of established connections)")
    return lines


def run(display: str, cmd: list[str], who: str = "host", fw: bool = True, timeout=30) -> str:
    res = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         cwd=ROOT, timeout=timeout)
    out = res.stdout.rstrip()
    fw_lines = new_log_lines() if (fw and fw_proc) else []
    sections[-1]["items"].append({"type": "run", "who": who, "cmd": display,
                                  "output": out, "fw": fw_lines})
    colour = "31" if who == "attacker" else "32"
    print(f"\033[{colour}m[{who}]$\033[0m {display}\n{out}")
    for line in fw_lines:
        print(f"   \033[2mpywall |\033[0m {line}")
    return out


def probe(args: str, who="attacker") -> str:
    cmd = [PY, "demo/probe.py", *args.split()]
    return run(f"python3 demo/probe.py {args}", in_ns(cmd) if who == "attacker" else cmd, who)


# ------------------------------------------------------------------- setup
def preflight() -> None:
    if os.geteuid() != 0:
        sys.exit("run as root:  sudo .venv/bin/python demo/live_demo.py")
    try:
        import netfilterqueue  # noqa: F401
    except ImportError:
        sys.exit("NetfilterQueue missing for this interpreter. Run with the venv python:\n"
                 "  sudo .venv/bin/python demo/live_demo.py")
    for tool in ("ip", "iptables", "curl", "ping"):
        if not shutil.which(tool):
            sys.exit(f"missing tool: {tool}")
    if sh(["ip", "netns", "list"]).stdout.find(NS) >= 0:
        sys.exit(f"namespace {NS} already exists - remove it with: sudo ip netns del {NS}")


def build_network() -> None:
    global firewalld_added
    for c in (["ip", "netns", "add", NS],
              ["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", ATK_IF],
              ["ip", "link", "set", ATK_IF, "netns", NS],
              ["ip", "addr", "add", f"{HOST_IP}/24", "dev", HOST_IF],
              ["ip", "link", "set", HOST_IF, "up"],
              in_ns(["ip", "addr", "add", f"{ATK_IP}/24", "dev", ATK_IF]),
              in_ns(["ip", "addr", "add", f"{ATK2_IP}/24", "dev", ATK_IF]),
              in_ns(["ip", "link", "set", ATK_IF, "up"]),
              in_ns(["ip", "link", "set", "lo", "up"])):
        sh(c)
    # firewalld (Fedora) would otherwise reject the test traffic itself
    if shutil.which("firewall-cmd") and sh(["firewall-cmd", "--state"], check=False).returncode == 0:
        sh(["firewall-cmd", "--zone=trusted", f"--add-interface={HOST_IF}"], check=False)
        firewalld_added = True


def start_services() -> None:
    web = Path(tempfile.mkdtemp(prefix="pywall-web-"))
    (web / "index.html").write_text("Hello from the protected host (10.99.0.1)\n")
    remote = Path(tempfile.mkdtemp(prefix="pywall-remote-"))
    (remote / "index.html").write_text("Hello from the remote side (10.99.0.2)\n")
    quiet = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for port in (80, 22, 3389):     # web server, plus stand-ins for SSH and RDP
        procs.append(subprocess.Popen([PY, "-m", "http.server", str(port), "--bind", HOST_IP,
                                       "--directory", str(web)], **quiet))
    for port in (80, 23):           # services on the remote side
        procs.append(subprocess.Popen(in_ns([PY, "-m", "http.server", str(port), "--bind", ATK_IP,
                                             "--directory", str(remote)]), **quiet))
    time.sleep(1.5)


def start_firewall() -> None:
    global fw_proc, log_pos
    LOG.unlink(missing_ok=True)
    log_pos = 0
    fw_proc = subprocess.Popen(
        [PY, "pywall.py", "-v", "--log", str(LOG), "live", "--interface", HOST_IF],
        cwd=ROOT, stdout=open(FW_OUT, "w"), stderr=subprocess.STDOUT)
    time.sleep(2)
    if fw_proc.poll() is not None:
        raise RuntimeError("PyWall failed to start:\n" + FW_OUT.read_text())


def stop_firewall() -> str:
    global fw_proc
    if not fw_proc:
        return ""
    fw_proc.send_signal(signal.SIGINT)
    try:
        fw_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        fw_proc.kill()
    fw_proc = None
    return FW_OUT.read_text()


def cleanup() -> None:
    stop_firewall()
    for p in procs:
        p.terminate()
    from firewall.live import _iptables_rules   # remove hooks if PyWall died early
    for chain, spec in _iptables_rules(False, HOST_IF):
        while sh(["iptables", "-D", chain, *spec], check=False).returncode == 0:
            pass
    if firewalld_added:
        sh(["firewall-cmd", "--zone=trusted", f"--remove-interface={HOST_IF}"], check=False)
    sh(["ip", "netns", "del", NS], check=False)
    sh(["ip", "link", "del", HOST_IF], check=False)
    uid, gid = int(os.environ.get("SUDO_UID", 0)), int(os.environ.get("SUDO_GID", 0))
    for f in (LOG, FW_OUT, SESSION):
        if f.exists() and uid:
            os.chown(f, uid, gid)


# ------------------------------------------------------------------ script
def demo() -> None:
    section("1/5  A private test network")
    say("attacker namespace (10.99.0.2, 10.99.0.3) <-veth-> this machine (10.99.0.1)")
    say("PyWall will filter ONLY the veth interface pw-host; real internet traffic is untouched")
    run("ip -br addr show pw-host", ["ip", "-br", "addr", "show", HOST_IF], fw=False)
    run("ip -br addr show pw-atk", in_ns(["ip", "-br", "addr", "show", ATK_IF]), "attacker", fw=False)

    section("2/5  Baseline: firewall OFF")
    say("services on 10.99.0.1: web (80), SSH stand-in (22), RDP stand-in (3389)")
    for port in (80, 22, 3389):
        probe(f"tcp {HOST_IP} {port}")
    run(f"ping -c 2 {HOST_IP}", in_ns(["ping", "-c", "2", "-q", HOST_IP]), "attacker", fw=False)
    say("everything is reachable")

    section("3/5  Start PyWall in live mode")
    start_firewall()
    head = FW_OUT.read_text().strip()
    sections[-1]["items"].append({"type": "run", "who": "host",
                                  "cmd": "sudo python3 pywall.py -v --log demo/live_firewall.log live --interface pw-host &",
                                  "output": re.sub(r"^\d\d:\d\d:\d\d\s+(?:(?:INFO|DEBUG|WARNING)\s+)?", "", head, flags=re.M),
                                  "fw": []})
    print(head)
    run("iptables -S INPUT | grep NFQUEUE; iptables -S OUTPUT | grep NFQUEUE",
        ["sh", "-c", "iptables -S INPUT | grep NFQUEUE; iptables -S OUTPUT | grep NFQUEUE"], fw=False)
    new_log_lines()

    section("4/5  Same traffic, firewall ON (real packets, live verdicts)")
    say("public web server: allowed by rule 6")
    run(f"curl -s http://{HOST_IP}/", in_ns(["curl", "-s", "-m", "3", f"http://{HOST_IP}/"]), "attacker")
    say("SSH from outside the LAN and RDP: silently dropped")
    probe(f"tcp {HOST_IP} 22")
    probe(f"tcp {HOST_IP} 3389")
    say("outbound: web allowed; telnet (port 23) rejected by rule 2, so the client is refused at once")
    run(f"curl -s http://{ATK_IP}/", ["curl", "-s", "-m", "3", f"http://{ATK_IP}/"], "host")
    probe(f"tcp {ATK_IP} 23", who="host")
    say("spoofed TCP ACK that belongs to no connection: dropped as INVALID")
    probe(f"spoof-ack {ATK_IP} {HOST_IP} 80")
    say("ping burst at 8/s against a 5/s limit: some echo requests dropped")
    run(f"ping -c 16 -i 0.125 {HOST_IP}",
        in_ns(["ping", "-c", "16", "-i", "0.125", "-q", HOST_IP]), "attacker")
    say("port scan of ports 1-40: IDS bans the scanner")
    probe(f"scan {HOST_IP} 1 40")
    say("the scanner is now banned - even the public web page is refused")
    run(f"curl -s -m 3 http://{HOST_IP}/ || echo 'no response (timed out)'",
        in_ns(["sh", "-c", f"curl -s -m 3 http://{HOST_IP}/ || echo 'no response (timed out)'"]), "attacker")
    say("SYN flood from the second address 10.99.0.3: 30 SYNs at once")
    probe(f"synflood {ATK2_IP} {HOST_IP} 80 30")

    section("5/5  Stop PyWall")
    report = stop_firewall()
    stats = report[report.find("=== Firewall statistics"):].strip() if "===" in report else report
    sections[-1]["items"].append({"type": "run", "who": "host", "cmd": "kill -INT %1   # Ctrl+C",
                                  "output": stats, "fw": []})
    print(stats)
    run("iptables -S | grep -c NFQUEUE || echo 'no NFQUEUE hooks left'",
        ["sh", "-c", "iptables -S | grep -c NFQUEUE || echo 'no NFQUEUE hooks left'"], fw=False)


def main() -> int:
    preflight()
    sys.path.insert(0, str(ROOT))
    ok = False
    try:
        build_network()
        start_services()
        demo()
        ok = True
    finally:
        cleanup()
        SESSION.write_text(json.dumps({"complete": ok, "recorded": time.strftime("%Y-%m-%d %H:%M"),
                                       "sections": sections}, indent=1))
        if os.environ.get("SUDO_UID"):
            os.chown(SESSION, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
        print(f"\nsession saved to {SESSION.relative_to(ROOT)}; test network removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
