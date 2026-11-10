#!/usr/bin/env python3
"""Write the simulator's traffic into a standard Ethernet pcap file, so the
`pcap` replay mode can be demonstrated without root (tcpdump needs root).
The file opens in Wireshark like any other capture."""

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from firewall.simulator import scenarios  # noqa: E402

out = sys.argv[1] if len(sys.argv) > 1 else "demo/sample.pcap"
t = 1_700_000_000.0
count = 0
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))   # 1 = Ethernet
    for step in scenarios():
        t += step.dt
        frame = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + step.raw
        sec, usec = int(t), int(round((t % 1) * 1e6)) % 1_000_000
        f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
        count += 1
print(f"wrote {count} packets to {out}")
