#!/usr/bin/env python3
"""Live dashboard lab: PyWall filtering REAL packets, with the dashboard running (needs root).

    sudo .venv/bin/python demo/live_dashboard_lab.py

Builds the same private test network as demo/live_demo.py (a network namespace
joined to this machine by a veth cable; only the veth interface "pw-host" is
filtered, so your real network is untouched) and starts the dashboard on live
traffic at http://127.0.0.1:8092.

Addresses on the "outside" end of the cable:
  10.99.0.4  a normal visitor browsing the web server (background traffic)
  10.99.0.2  the attacker (SSH/RDP attempts, ping burst, port scan, spoofed ACK)
  10.99.0.3  a second attacker (SYN flood)

Attacks run when a command file appears in the control directory (default
/tmp/pywall-lab), so a screen recorder can trigger them in step with the video:
write "NNN.cmd" containing one action; the result is written to "NNN.done".
Actions: web ssh rdp telnet outbound spoof ping scan synflood quit.
Without a recorder, type the same actions at the prompt. Ctrl+C or "quit"
stops PyWall and removes the test network.
"""

from __future__ import annotations

import argparse
import os
import random
import select
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))
import live_demo as lab  # noqa: E402  (reuses its network setup and cleanup)

PY = sys.executable
NS, HOST_IF = lab.NS, lab.HOST_IF
HOST_IP, ATK_IP, ATK2_IP = lab.HOST_IP, lab.ATK_IP, lab.ATK2_IP
VISITOR_IP = "10.99.0.4"
PORT = 8092

server: subprocess.Popen | None = None
stop = threading.Event()


def ns(cmd: list[str]) -> list[str]:
    return ["ip", "netns", "exec", NS, *cmd]


def out(cmd: list[str], timeout=30) -> str:
    try:
        r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, cwd=ROOT)
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return "no response (timed out)"


def probe(*args: str, inside=True) -> str:
    cmd = [PY, "demo/probe.py", *args]
    return out(ns(cmd) if inside else cmd)


def timed_curl(url: str, inside=True, src: str | None = None) -> str:
    cmd = ["curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "HTTP %{http_code} in %{time_total}s"]
    if src:
        cmd += ["--interface", src]
    r = out((ns if inside else list)(cmd + [url]))
    return r if not r.startswith("HTTP 000") else f"no response ({r.split(' in ')[-1]})"


ACTIONS = {
    "web": lambda: "visitor 10.99.0.4 -> web server :80: " + timed_curl(f"http://{HOST_IP}/", src=VISITOR_IP),
    "ssh": lambda: probe("tcp", HOST_IP, "22"),
    "rdp": lambda: probe("tcp", HOST_IP, "3389"),
    "telnet": lambda: probe("tcp", ATK_IP, "23", inside=False),
    "outbound": lambda: "this host -> 10.99.0.2:80: " + timed_curl(f"http://{ATK_IP}/", inside=False),
    "spoof": lambda: probe("spoof-ack", ATK_IP, HOST_IP, "80"),
    "ping": lambda: next((ln for ln in out(ns(["ping", "-c", "16", "-i", "0.125", "-q", "-I", ATK_IP, HOST_IP])).splitlines()
                          if "transmitted" in ln), "ping failed"),
    "scan": lambda: probe("scan", HOST_IP, "1", "40"),
    "scanned-web": lambda: "attacker 10.99.0.2 -> web server :80: " + timed_curl(f"http://{HOST_IP}/", src=ATK_IP),
    "synflood": lambda: probe("synflood", ATK2_IP, HOST_IP, "80", "40"),
}


def background() -> None:
    """Normal traffic so the flow map is never empty: a visitor browsing, this host fetching, pings."""
    n = 0
    while not stop.is_set():
        n += 1
        subprocess.run(ns(["curl", "-s", "-m", "2", "-o", "/dev/null", "--interface", VISITOR_IP, f"http://{HOST_IP}/"]),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if n % 3 == 0:
            subprocess.run(["curl", "-s", "-m", "2", "-o", "/dev/null", f"http://{ATK_IP}/"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if n % 4 == 0:
            subprocess.run(ns(["ping", "-c", "1", "-W", "1", "-I", VISITOR_IP, HOST_IP]),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop.wait(random.uniform(0.25, 0.6))


def run_action(name: str) -> str:
    fn = ACTIONS.get(name)
    if not fn:
        return f"unknown action {name!r}; choose from: {' '.join(ACTIONS)} quit"
    result = fn()
    print(f"\033[1m[{name}]\033[0m {result}", flush=True)
    return result


def watch(control: Path) -> None:
    while not stop.is_set():
        for f in sorted(control.glob("*.cmd")):
            name = f.read_text().strip()
            f.unlink()
            if name == "quit":
                stop.set()
                return
            res = run_action(name)
            done = f.with_suffix(".done")
            done.write_text(res)
            os.chmod(done, 0o666)
        time.sleep(0.1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--control", default="/tmp/pywall-lab", help="directory watched for command files")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root:  sudo .venv/bin/python demo/live_dashboard_lab.py")
    try:
        import netfilterqueue  # noqa: F401
    except ImportError:
        sys.exit("NetfilterQueue missing for this interpreter; use: sudo .venv/bin/python demo/live_dashboard_lab.py")
    for tool in ("ip", "iptables", "curl", "ping"):
        if not shutil.which(tool):
            sys.exit(f"missing tool: {tool}")
    if NS in out(["ip", "netns", "list"]):
        sys.exit(f"namespace {NS} already exists - remove it with: sudo ip netns del {NS}")

    control = Path(args.control)
    shutil.rmtree(control, ignore_errors=True)
    control.mkdir(parents=True)
    os.chmod(control, 0o777)

    global server
    try:
        lab.build_network()
        subprocess.run(ns(["ip", "addr", "add", f"{VISITOR_IP}/24", "dev", lab.ATK_IF]), check=True)
        lab.start_services()
        server = subprocess.Popen([PY, "pywall.py", "serve", "--source", "live", "-i", HOST_IF,
                                   "--port", str(PORT), "--no-history"], cwd=ROOT)
        time.sleep(3)
        if server.poll() is not None:
            raise RuntimeError("PyWall failed to start")
        threading.Thread(target=background, daemon=True).start()
        threading.Thread(target=watch, args=(control,), daemon=True).start()
        print(f"\n\033[1;32mLab ready.\033[0m Dashboard: http://127.0.0.1:{PORT}  (filtering only {HOST_IF})")
        print(f"Waiting for commands in {control}; or type one of: {' '.join(ACTIONS)} quit\n", flush=True)
        interactive = sys.stdin.isatty()
        while not stop.is_set():
            if not interactive or not select.select([sys.stdin], [], [], 0.3)[0]:
                stop.wait(0.3)
                continue
            line = sys.stdin.readline().strip()
            if line == "quit":
                stop.set()
            elif line:
                run_action(line)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        if server and server.poll() is None:
            server.send_signal(2)
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
        lab.cleanup()
        shutil.rmtree(control, ignore_errors=True)
        left = out(["sh", "-c", "iptables -S | grep -c NFQUEUE || true"])
        print(f"\nPyWall stopped; test network removed; NFQUEUE hooks left: {left}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
