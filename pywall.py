#!/usr/bin/env python3
"""PyWall command-line interface.

  python3 pywall.py simulate                 # run the built-in attack/traffic scenarios
  python3 pywall.py pcap capture.pcap        # replay a tcpdump capture through the rules
  python3 pywall.py check                    # validate and print the rule set
  sudo python3 pywall.py live [--dry-run]    # filter this machine's real traffic
"""

import argparse
import logging
import os
import sys

from firewall.colors import colour_log_message, paint
from firewall.engine import Firewall
from firewall.rules import RuleError, load_config


class ConsoleFormatter(logging.Formatter):
    """Terminal log format: grey time, coloured verdicts (plain when piped)."""

    def format(self, record):
        msg = colour_log_message(record.getMessage(), warning=record.levelno >= logging.WARNING)
        return f"{paint(self.formatTime(record, '%H:%M:%S'), 'grey')}  {msg}"


def setup_logging(verbose: bool, logfile: str | None) -> None:
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(ConsoleFormatter())
    handlers = [console]
    if logfile:
        plain = logging.FileHandler(logfile)
        plain.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
        handlers.append(plain)
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=handlers)


def cmd_check(cfg, _args):
    print(f"default policy: {paint.verdict(cfg.default_policy, 0)}   stateful: {cfg.stateful}   "
          f"drop invalid: {cfg.drop_invalid}   IDS: {cfg.ids.get('enabled', True)}")
    print(paint(f"{'#':>3}  {'ACTION':<6} {'DIR':<4} {'PROTO':<5} {'SRC':<18} {'DST PORT / TYPE':<20} NAME", "bold"))
    for r in cfg.rules:
        proto = {1: "icmp", 6: "tcp", 17: "udp"}.get(r.protocol, "any")
        src = ",".join(map(str, r.src)) if r.src else "any"
        ports = ",".join(f"{a}" if a == b else f"{a}-{b}" for a, b in r.dst_port) if r.dst_port else "any"
        if r.icmp_type is not None:
            ports = f"icmp type {r.icmp_type}"
        if r.rate_limit:
            ports += f" ({r.rate_limit[0]}/{r.rate_limit[1]}s)"
        print(f"{r.id:>3}  {paint.verdict(r.action)} {r.direction:<4} {proto:<5} {src:<18} {ports:<20} {r.name}")
    print(paint("Rule set is valid.", "green"))
    return 0


def cmd_simulate(cfg, args):
    from firewall.simulator import VirtualClock, run_simulation
    logging.getLogger("firewall").setLevel(logging.ERROR)   # the simulator prints its own table
    clock = VirtualClock()
    ok = run_simulation(Firewall(cfg, clock_fn=clock), clock, verbose=args.verbose)
    return 0 if ok else 1


def cmd_pcap(cfg, args):
    from firewall.pcap import read_pcap
    ts_box = [0.0]
    fw = Firewall(cfg, clock_fn=lambda: ts_box[0])
    for ts, raw in read_pcap(args.file):
        ts_box[0] = ts
        fw.process(raw)
    print(fw.report())
    return 0


def cmd_live(cfg, args):
    from firewall.live import run_live
    run_live(Firewall(cfg), dry_run=args.dry_run, include_loopback=args.include_loopback,
             interface=args.interface)
    return 0


def cmd_doctor(cfg, args):
    """Pre-flight checks for a live demo on a real network. Changes nothing."""
    import os
    import shutil
    import socket
    import subprocess
    from firewall.netinfo import interface_addresses
    ok = True

    def line(good, what, detail=""):
        nonlocal ok
        ok = ok and good is not False
        mark = paint("ok  ", "green") if good else paint("warn", "yellow") if good is None else paint("FAIL", "bold", "red")
        print(f"  {mark}  {what}" + (f"  {paint(detail, 'grey')}" if detail else ""))

    print(paint("PyWall live-demo check", "bold"))
    line(os.geteuid() == 0, "running as root", "" if os.geteuid() == 0 else "live mode needs sudo")
    try:
        import netfilterqueue  # noqa: F401
        line(True, "NetfilterQueue importable", sys.executable)
    except ImportError:
        line(False, "NetfilterQueue importable", f"not for {sys.executable}; use .venv/bin/python")
    line(bool(shutil.which("iptables")), "iptables present")
    line(bool(args.interface), "network interface", f"{args.interface} {', '.join(interface_addresses(args.interface)) if args.interface else ''}")
    line(bool(cfg.local_networks), "local network ($LAN)", ", ".join(map(str, cfg.local_networks)))
    line(True, "rule set valid", f"{len(cfg.rules)} rules, default policy {cfg.default_policy}")
    line(cfg.pickup_outbound or None, "connections open before start are adopted",
         "" if cfg.pickup_outbound else "pickup_outbound is off: open connections will be cut")
    with socket.socket() as s_:
        free = s_.connect_ex(("127.0.0.1", args.port)) != 0
    line(free or None, f"port {args.port} free for the dashboard", "" if free else "something is listening; use --port")
    fwd = subprocess.run(["systemctl", "is-active", "firewalld"], capture_output=True, text=True).stdout.strip()
    line(None if fwd == "active" else True, "firewalld", "active: it also filters, after PyWall; that is fine"
         if fwd == "active" else fwd or "not found")
    print()
    print(("Ready. Rehearse with:\n  " if ok else "Fix the FAIL lines, then run:\n  ") +
          f"sudo .venv/bin/python pywall.py serve --source live -i {args.interface or 'auto'} --lan auto --dry-run")
    return 0 if ok else 1


def cmd_serve(cfg, args):
    import time
    from firewall.monitor import Monitor
    from firewall.server import serve
    fw = Firewall(cfg)
    if args.source == "live":
        lan = ", ".join(map(str, cfg.local_networks)) or "not set"
        source = {"kind": "live", "dryRun": bool(args.dry_run),
                  "label": f"Live: netfilter NFQUEUE on {args.interface or 'all interfaces'}, LAN {lan}"
                  + (" (dry run: verdicts shown, nothing dropped)" if args.dry_run else "")}
    elif args.source == "pcap":
        if not args.pcap:
            print("--source pcap needs --pcap FILE", file=sys.stderr)
            return 2
        source = {"kind": "pcap", "label": f"Replay of {args.pcap}"}
    else:
        source = {"kind": "simulated", "label": "Simulated traffic (real packets, synthetic pattern)"}
    source["readOnly"] = bool(args.read_only)
    monitor = Monitor(fw, source)
    serve(fw, monitor, args.config, args.host, args.port, read_only=args.read_only)
    print(paint(f"PyWall dashboard: http://{args.host}:{args.port}/", "bold", "green") + f"  [{source['label']}]")
    try:
        if args.source == "live":
            from firewall.live import run_live
            run_live(fw, dry_run=args.dry_run, interface=args.interface)
        elif args.source == "pcap":
            from firewall.pcap import read_pcap
            while True:
                prev = None
                for ts, raw in read_pcap(args.pcap):
                    if prev is not None:
                        time.sleep(min(max(ts - prev, 0.0), 2.0) / args.speed)
                    prev = ts
                    with fw.lock:
                        fw.process(raw)
                if not args.loop:
                    print("pcap replay finished; dashboard stays up. Ctrl+C to stop.")
                    while True:
                        time.sleep(3600)
                time.sleep(2)
        else:
            from firewall.traffic import TrafficGenerator
            TrafficGenerator(fw, seed=args.seed, speed=args.speed).run()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="pywall", description="Stateful packet-filtering firewall")
    p.add_argument("-c", "--config", default="config/rules.json", help="rule set (JSON)")
    p.add_argument("-v", "--verbose", action="store_true", help="log every packet, not only drops")
    p.add_argument("--log", metavar="FILE", help="also write the log to FILE")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="validate and print the rule set")
    sub.add_parser("simulate", help="run built-in traffic and attack scenarios")
    pc = sub.add_parser("pcap", help="replay a pcap capture through the firewall")
    pc.add_argument("file")
    lv = sub.add_parser("live", help="filter real traffic via NFQUEUE (root)")
    lv.add_argument("--dry-run", action="store_true", help="log verdicts but drop nothing")
    lv.add_argument("--include-loopback", action="store_true", help="also filter the lo interface")
    lv.add_argument("-i", "--interface", help="only filter traffic on this interface ('auto' = the default route's)")
    lv.add_argument("--lan", help="local networks: 'auto' (detect) or CIDR[,CIDR]; $LAN in rules follows it")
    dr = sub.add_parser("doctor", help="check this machine is ready for a live demo")
    dr.add_argument("-i", "--interface", default="auto")
    dr.add_argument("--lan", default="auto")
    dr.add_argument("--port", type=int, default=8080)
    sv = sub.add_parser("serve", help="run the web dashboard with a traffic source")
    sv.add_argument("--source", choices=["simulated", "pcap", "live"], default="simulated",
                    help="simulated (default, no root), pcap replay, or live NFQUEUE (root)")
    sv.add_argument("--pcap", metavar="FILE", help="capture to replay with --source pcap")
    sv.add_argument("--loop", action="store_true", help="replay the pcap forever")
    sv.add_argument("--speed", type=float, default=1.0, help="traffic speed multiplier (simulated/pcap)")
    sv.add_argument("--seed", type=int, help="random seed for the simulated traffic")
    sv.add_argument("-i", "--interface", help="live mode: only filter this interface ('auto' = the default route's)")
    sv.add_argument("--lan", help="local networks: 'auto' (detect) or CIDR[,CIDR]; $LAN in rules follows it")
    sv.add_argument("--dry-run", action="store_true", help="live mode: log verdicts but drop nothing")
    sv.add_argument("--host", default="127.0.0.1", help="address to listen on (0.0.0.0 for a public demo)")
    sv.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)),
                    help="port to listen on (default: $PORT if set, else 8080)")
    sv.add_argument("--read-only", action="store_true", help="refuse rule changes (for a public demo)")
    args = p.parse_args(argv)

    setup_logging(args.verbose, args.log)
    lan = None
    if getattr(args, "interface", None) == "auto":
        from firewall.netinfo import default_interface
        args.interface = default_interface()
        if not args.interface:
            print(paint("error:", "bold", "red") + " no default network interface found; pass -i IFACE", file=sys.stderr)
            return 2
    if getattr(args, "lan", None):
        if args.lan == "auto":
            from firewall.netinfo import default_interface, interface_networks
            dev = args.interface or default_interface()
            lan = interface_networks(dev) if dev else []
            if not lan:
                print(paint("error:", "bold", "red") + " could not detect the local network; pass --lan CIDR", file=sys.stderr)
                return 2
        else:
            lan = [x.strip() for x in args.lan.split(",") if x.strip()]
    try:
        cfg = load_config(args.config, lan=lan)
    except (OSError, ValueError, RuleError) as exc:
        print(f"{paint('error:', 'bold', 'red')} loading {args.config}: {exc}", file=sys.stderr)
        return 2
    return {"check": cmd_check, "simulate": cmd_simulate, "pcap": cmd_pcap, "live": cmd_live,
            "serve": cmd_serve, "doctor": cmd_doctor}[args.cmd](cfg, args)


if __name__ == "__main__":
    sys.exit(main())
