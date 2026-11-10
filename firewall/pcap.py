"""Minimal reader for classic libpcap files (as written by tcpdump -w),
so captured real traffic can be replayed through the firewall offline."""

from __future__ import annotations

import struct
from typing import Iterator

LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2 = 1, 101, 113, 276
IP_ETHERTYPES = (0x0800, 0x86DD)       # IPv4, IPv6


def read_pcap(path: str) -> Iterator[tuple[float, bytes]]:
    """Yield (timestamp, ip_bytes) for every IPv4 and IPv6 packet in the file."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError("not a pcap file")
        magic = header[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        else:
            raise ValueError("unsupported capture format (use classic pcap: tcpdump -w file.pcap)")
        nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(endian + "IIII", rec)
            frame = f.read(incl)
            ts = sec + frac / (1e9 if nano else 1e6)
            ip = _strip_link(frame, linktype)
            if ip is not None:
                yield ts, ip


def _strip_link(frame: bytes, linktype: int) -> bytes | None:
    if linktype == LINKTYPE_RAW:
        data = frame
    elif linktype == LINKTYPE_ETHERNET:
        offset, ethertype = 14, struct.unpack("!H", frame[12:14])[0]
        while ethertype in (0x8100, 0x88A8):        # VLAN tags
            ethertype = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        if ethertype not in IP_ETHERTYPES:
            return None
        data = frame[offset:]
    elif linktype == LINKTYPE_LINUX_SLL:
        if struct.unpack("!H", frame[14:16])[0] not in IP_ETHERTYPES:
            return None
        data = frame[16:]
    elif linktype == LINKTYPE_LINUX_SLL2:
        if struct.unpack("!H", frame[0:2])[0] not in IP_ETHERTYPES:
            return None
        data = frame[20:]
    else:
        raise ValueError(f"unsupported link type {linktype}")
    return data if data and data[0] >> 4 in (4, 6) else None
