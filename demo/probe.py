#!/usr/bin/env python3
"""Small network probe used by the live demo (run inside the attacker namespace).

  probe.py tcp HOST PORT            -> open / closed (refused) / filtered (no reply)
  probe.py scan HOST FIRST LAST     -> parallel TCP connect scan of a port range
  probe.py spoof-ack SRC DST PORT   -> send a lone TCP ACK (not part of any connection)
  probe.py synflood SRC DST PORT N  -> send N TCP SYNs as fast as possible
The last two use a raw socket and need root.
"""

import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from firewall.packet import ACK, SYN, build_tcp  # noqa: E402


def tcp_state(host: str, port: int, timeout: float = 2.0) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return "open"
    except ConnectionRefusedError:
        return "closed (connection refused)"
    except (socket.timeout, TimeoutError):
        return "filtered (no reply - packet dropped)"
    except OSError as exc:
        return f"error ({exc.strerror})"
    finally:
        s.close()


def raw_send(packets, dst: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    for p in packets:
        s.sendto(p, (dst, 0))
    s.close()


def main(argv):
    cmd = argv[0]
    if cmd == "tcp":
        host, port = argv[1], int(argv[2])
        t = time.monotonic()
        state = tcp_state(host, port)
        print(f"{host}:{port} -> {state}  [{time.monotonic() - t:.2f}s]")
    elif cmd == "scan":
        host, lo, hi = argv[1], int(argv[2]), int(argv[3])
        ports = range(lo, hi + 1)
        with ThreadPoolExecutor(max_workers=len(ports)) as pool:
            states = dict(zip(ports, pool.map(lambda p: tcp_state(host, p, 1.5), ports)))
        groups = {}
        for p, st in states.items():
            groups.setdefault(st.split(" ")[0], []).append(p)
        print(f"scanned {len(ports)} ports on {host}:")
        for st in ("open", "closed", "filtered"):
            if st in groups:
                ps = groups[st]
                shown = ",".join(map(str, ps)) if len(ps) <= 12 else f"{ps[0]}-{ps[-1]} ({len(ps)} ports)"
                print(f"  {st:<9} {shown}")
    elif cmd == "spoof-ack":
        src, dst, port = argv[1], argv[2], int(argv[3])
        raw_send([build_tcp(src, dst, 44444, port, ACK, seq=12345, ack=67890)], dst)
        print(f"sent a lone TCP ACK {src}:44444 -> {dst}:{port} (no handshake before it)")
    elif cmd == "synflood":
        src, dst, port, n = argv[1], argv[2], int(argv[3]), int(argv[4])
        t = time.monotonic()
        raw_send([build_tcp(src, dst, 20000 + i, port, SYN, seq=i) for i in range(n)], dst)
        print(f"sent {n} SYNs {src} -> {dst}:{port} in {time.monotonic() - t:.3f}s")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
