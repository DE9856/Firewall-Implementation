"""IPv4 / TCP / UDP / ICMP packet parsing and building.

Packets are parsed straight from raw bytes with ``struct`` (no third-party
library), exactly as they arrive from the kernel through NFQUEUE: the buffer
starts at the IPv4 header.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_NAMES = {PROTO_ICMP: "icmp", PROTO_TCP: "tcp", PROTO_UDP: "udp"}
PROTO_NUMBERS = {v: k for k, v in PROTO_NAMES.items()}

# TCP flag bits (byte 13 of the TCP header)
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
_FLAG_LETTERS = [(SYN, "S"), (ACK, "A"), (FIN, "F"), (RST, "R"), (PSH, "P"), (URG, "U")]


class PacketError(ValueError):
    """Raised when a buffer is not a valid IPv4 packet."""


@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    protocol: int
    ttl: int
    length: int
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int = 0
    icmp_type: int | None = None
    icmp_code: int | None = None

    @property
    def proto_name(self) -> str:
        return PROTO_NAMES.get(self.protocol, str(self.protocol))

    def has_flag(self, flag: int) -> bool:
        return bool(self.tcp_flags & flag)

    @property
    def flag_str(self) -> str:
        return "".join(letter for bit, letter in _FLAG_LETTERS if self.tcp_flags & bit)

    def summary(self) -> str:
        if self.protocol in (PROTO_TCP, PROTO_UDP):
            s = f"{self.proto_name.upper()} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
            if self.protocol == PROTO_TCP:
                s += f" [{self.flag_str or '.'}]"
            return s
        if self.protocol == PROTO_ICMP:
            return f"ICMP {self.src_ip} -> {self.dst_ip} type={self.icmp_type} code={self.icmp_code}"
        return f"PROTO-{self.protocol} {self.src_ip} -> {self.dst_ip}"


def parse_packet(data: bytes) -> Packet:
    """Parse a raw IPv4 packet (starting at the IP header)."""
    if len(data) < 20:
        raise PacketError("buffer shorter than minimum IPv4 header")
    ver_ihl, _tos, total_len, _ident, _frag, ttl, proto, _csum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", data[:20]
    )
    version, ihl = ver_ihl >> 4, (ver_ihl & 0x0F) * 4
    if version != 4:
        raise PacketError(f"not IPv4 (version={version})")
    if ihl < 20 or len(data) < ihl:
        raise PacketError("bad IPv4 header length")

    pkt = Packet(
        src_ip=socket.inet_ntoa(src),
        dst_ip=socket.inet_ntoa(dst),
        protocol=proto,
        ttl=ttl,
        length=total_len,
    )
    payload = data[ihl:]
    if proto == PROTO_TCP:
        if len(payload) < 20:
            raise PacketError("truncated TCP header")
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", payload[:4])
        pkt.tcp_flags = payload[13]
    elif proto == PROTO_UDP:
        if len(payload) < 8:
            raise PacketError("truncated UDP header")
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", payload[:4])
    elif proto == PROTO_ICMP:
        if len(payload) < 4:
            raise PacketError("truncated ICMP header")
        pkt.icmp_type, pkt.icmp_code = payload[0], payload[1]
    return pkt


# ---------------------------------------------------------------- building --
def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip_header(src: str, dst: str, proto: int, payload_len: int, ttl: int = 64) -> bytes:
    total = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def build_tcp(src: str, dst: str, sport: int, dport: int, flags: int = SYN,
              payload: bytes = b"", seq: int = 0, ack: int = 0) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    csum = checksum(_pseudo(src, dst, PROTO_TCP, len(seg)) + seg)
    seg = seg[:16] + struct.pack("!H", csum) + seg[18:]
    return _ip_header(src, dst, PROTO_TCP, len(seg)) + seg


def build_udp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"") -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = checksum(_pseudo(src, dst, PROTO_UDP, len(seg)) + seg) or 0xFFFF
    seg = seg[:6] + struct.pack("!H", csum) + seg[8:]
    return _ip_header(src, dst, PROTO_UDP, len(seg)) + seg


def build_icmp(src: str, dst: str, icmp_type: int = 8, code: int = 0, payload: bytes = b"ping") -> bytes:
    msg = struct.pack("!BBHHH", icmp_type, code, 0, 1, 1) + payload
    msg = msg[:2] + struct.pack("!H", checksum(msg)) + msg[4:]
    return _ip_header(src, dst, PROTO_ICMP, len(msg)) + msg


# --------------------------------------------------------------- dissection
def _f(name, offset, length, value, note=""):
    return {"name": name, "offset": offset, "length": length, "value": value, "note": note}


def dissect(data: bytes) -> list[dict]:
    """Break the kept header bytes into labelled fields, layer by layer, with the
    byte offset and length of each (bit fields share their byte). Used by the
    dashboard's packet inspector; returns what can be decoded from `data`."""
    layers = []
    if len(data) < 20 or data[0] >> 4 != 4:
        return layers
    ihl = (data[0] & 0x0F) * 4
    (_vi, tos, total, ident, frag, ttl, proto, csum, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:20])
    ok = checksum(data[:ihl]) == 0 if len(data) >= ihl else None
    flags = []
    if frag & 0x4000:
        flags.append("DF")
    if frag & 0x2000:
        flags.append("MF")
    layers.append({"layer": "IPv4", "offset": 0, "length": ihl, "fields": [
        _f("Version", 0, 1, 4, "upper 4 bits"),
        _f("Header length", 0, 1, ihl, f"{ihl // 4} x 32-bit words"),
        _f("DSCP / ECN", 1, 1, f"0x{tos:02x}"),
        _f("Total length", 2, 2, total, "bytes, header + payload"),
        _f("Identification", 4, 2, f"0x{ident:04x}"),
        _f("Flags", 6, 1, " ".join(flags) or "none", "DF = don't fragment, MF = more fragments"),
        _f("Fragment offset", 6, 2, frag & 0x1FFF),
        _f("TTL", 8, 1, ttl, "hops left before the packet is discarded"),
        _f("Protocol", 9, 1, f"{proto} ({PROTO_NAMES.get(proto, 'other')})"),
        _f("Header checksum", 10, 2, f"0x{csum:04x}", "valid" if ok else "invalid" if ok is False else ""),
        _f("Source address", 12, 4, socket.inet_ntoa(src)),
        _f("Destination address", 16, 4, socket.inet_ntoa(dst)),
    ]})
    seg, o = data[ihl:], ihl
    if proto == PROTO_TCP and len(seg) >= 20:
        sp, dp, seq, ack, off, fl, win, cs, urg = struct.unpack("!HHIIBBHHH", seg[:20])
        names = [n for b, n in ((SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"), (URG, "URG")) if fl & b]
        layers.append({"layer": "TCP", "offset": o, "length": (off >> 4) * 4, "fields": [
            _f("Source port", o, 2, sp), _f("Destination port", o + 2, 2, dp),
            _f("Sequence number", o + 4, 4, seq), _f("Acknowledgment number", o + 8, 4, ack),
            _f("Data offset", o + 12, 1, (off >> 4) * 4, "TCP header length in bytes"),
            _f("Flags", o + 13, 1, " ".join(names) or "none", f"0x{fl:02x}"),
            _f("Window", o + 14, 2, win, "receive window, bytes"),
            _f("Checksum", o + 16, 2, f"0x{cs:04x}"), _f("Urgent pointer", o + 18, 2, urg),
        ]})
    elif proto == PROTO_UDP and len(seg) >= 8:
        sp, dp, ln, cs = struct.unpack("!HHHH", seg[:8])
        layers.append({"layer": "UDP", "offset": o, "length": 8, "fields": [
            _f("Source port", o, 2, sp), _f("Destination port", o + 2, 2, dp),
            _f("Length", o + 4, 2, ln, "UDP header + data, bytes"), _f("Checksum", o + 6, 2, f"0x{cs:04x}"),
        ]})
    elif proto == PROTO_ICMP and len(seg) >= 4:
        t, c, cs = struct.unpack("!BBH", seg[:4])
        kinds = {0: "echo reply", 3: "destination unreachable", 8: "echo request", 11: "time exceeded"}
        fields = [_f("Type", o, 1, f"{t} ({kinds.get(t, 'other')})"), _f("Code", o + 1, 1, c),
                  _f("Checksum", o + 2, 2, f"0x{cs:04x}")]
        if t in (0, 8) and len(seg) >= 8:
            ident, sq = struct.unpack("!HH", seg[4:8])
            fields += [_f("Identifier", o + 4, 2, ident), _f("Sequence", o + 6, 2, sq)]
        layers.append({"layer": "ICMP", "offset": o, "length": len(fields) > 3 and 8 or 4, "fields": fields})
    return layers
