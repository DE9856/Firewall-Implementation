"""IPv4 / IPv6 / TCP / UDP / ICMP packet parsing and building.

Packets are parsed straight from raw bytes with ``struct`` (no third-party
library), exactly as they arrive from the kernel through NFQUEUE: the buffer
starts at the IP header (version 4 or 6).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58
PROTO_NAMES = {PROTO_ICMP: "icmp", PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMPV6: "icmpv6"}
PROTO_NUMBERS = {v: k for k, v in PROTO_NAMES.items()}

# TCP flag bits (byte 13 of the TCP header)
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
_FLAG_LETTERS = [(SYN, "S"), (ACK, "A"), (FIN, "F"), (RST, "R"), (PSH, "P"), (URG, "U")]

# ICMP echo types differ between versions: (request, reply)
ECHO = {4: (8, 0), 6: (128, 129)}
ICMP_KINDS = {
    4: {0: "echo reply", 3: "destination unreachable", 8: "echo request", 11: "time exceeded"},
    6: {1: "destination unreachable", 2: "packet too big", 3: "time exceeded", 128: "echo request",
        129: "echo reply", 133: "router solicitation", 134: "router advertisement",
        135: "neighbor solicitation", 136: "neighbor advertisement"},
}
# IPv6 extension headers PyWall walks past to reach the transport header
_V6_EXT = {0, 43, 44, 51, 60}


class PacketError(ValueError):
    """Raised when a buffer is not a valid IPv4 or IPv6 packet."""


@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    protocol: int
    ttl: int                       # IPv4 TTL, or IPv6 hop limit
    length: int
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int = 0
    icmp_type: int | None = None
    icmp_code: int | None = None
    version: int = 4
    seq: int = 0                   # TCP sequence / acknowledgment numbers (for REJECT replies)
    ack: int = 0
    payload_len: int = 0           # TCP payload bytes
    header_len: int = 20           # bytes of IP header incl. IPv6 extension headers

    @property
    def proto_name(self) -> str:
        return PROTO_NAMES.get(self.protocol, str(self.protocol))

    @property
    def is_icmp(self) -> bool:
        return self.protocol in (PROTO_ICMP, PROTO_ICMPV6)

    @property
    def is_echo_request(self) -> bool:
        return self.is_icmp and self.icmp_type == ECHO[self.version][0]

    @property
    def is_echo_reply(self) -> bool:
        return self.is_icmp and self.icmp_type == ECHO[self.version][1]

    def has_flag(self, flag: int) -> bool:
        return bool(self.tcp_flags & flag)

    @property
    def flag_str(self) -> str:
        return "".join(letter for bit, letter in _FLAG_LETTERS if self.tcp_flags & bit)

    def summary(self) -> str:
        def ep(ip, port):
            return f"[{ip}]:{port}" if self.version == 6 else f"{ip}:{port}"
        if self.protocol in (PROTO_TCP, PROTO_UDP):
            s = f"{self.proto_name.upper()} {ep(self.src_ip, self.src_port)} -> {ep(self.dst_ip, self.dst_port)}"
            if self.protocol == PROTO_TCP:
                s += f" [{self.flag_str or '.'}]"
            return s
        if self.is_icmp:
            return f"{self.proto_name.upper()} {self.src_ip} -> {self.dst_ip} type={self.icmp_type} code={self.icmp_code}"
        return f"PROTO-{self.protocol} {self.src_ip} -> {self.dst_ip}"


def parse_packet(data: bytes) -> Packet:
    """Parse a raw IP packet (starting at the IPv4 or IPv6 header)."""
    if not data:
        raise PacketError("empty buffer")
    version = data[0] >> 4
    if version == 6:
        return _parse_v6(data)
    if len(data) < 20:
        raise PacketError("buffer shorter than minimum IPv4 header")
    ver_ihl, _tos, total_len, _ident, _frag, ttl, proto, _csum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", data[:20]
    )
    version, ihl = ver_ihl >> 4, (ver_ihl & 0x0F) * 4
    if version != 4:
        raise PacketError(f"not IPv4 or IPv6 (version={version})")
    if ihl < 20 or len(data) < ihl:
        raise PacketError("bad IPv4 header length")
    pkt = Packet(src_ip=socket.inet_ntoa(src), dst_ip=socket.inet_ntoa(dst), protocol=proto,
                 ttl=ttl, length=total_len, header_len=ihl)
    _parse_transport(pkt, data[ihl:], total_len - ihl)
    return pkt


def _parse_v6(data: bytes) -> Packet:
    if len(data) < 40:
        raise PacketError("buffer shorter than the IPv6 header (40 bytes)")
    _vtf, payload_len, nxt, hop = struct.unpack("!IHBB", data[:8])
    pkt = Packet(src_ip=socket.inet_ntop(socket.AF_INET6, data[8:24]),
                 dst_ip=socket.inet_ntop(socket.AF_INET6, data[24:40]),
                 protocol=nxt, ttl=hop, length=40 + payload_len, version=6)
    off = 40
    while pkt.protocol in _V6_EXT:
        if len(data) < off + 8:
            raise PacketError("truncated IPv6 extension header")
        nxt_hdr = data[off]
        if pkt.protocol == 44:                       # fragment header: fixed 8 bytes
            frag_off = struct.unpack("!H", data[off + 2:off + 4])[0] >> 3
            off += 8
            pkt.protocol = nxt_hdr
            if frag_off:                             # a later fragment has no transport header
                pkt.header_len = off
                return pkt
            continue
        size = (data[off + 1] + 2) * 4 if pkt.protocol == 51 else (data[off + 1] + 1) * 8
        pkt.protocol, off = nxt_hdr, off + size
    pkt.header_len = off
    _parse_transport(pkt, data[off:], pkt.length - off)
    return pkt


def _parse_transport(pkt: Packet, payload: bytes, segment_len: int) -> None:
    proto = pkt.protocol
    if proto == PROTO_TCP:
        if len(payload) < 20:
            raise PacketError("truncated TCP header")
        pkt.src_port, pkt.dst_port, pkt.seq, pkt.ack = struct.unpack("!HHII", payload[:12])
        pkt.tcp_flags = payload[13]
        pkt.payload_len = max(0, segment_len - (payload[12] >> 4) * 4)
    elif proto == PROTO_UDP:
        if len(payload) < 8:
            raise PacketError("truncated UDP header")
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", payload[:4])
    elif proto in (PROTO_ICMP, PROTO_ICMPV6):
        if len(payload) < 4:
            raise PacketError("truncated ICMP header")
        pkt.icmp_type, pkt.icmp_code = payload[0], payload[1]


# ---------------------------------------------------------------- building --
def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def is_v6(addr: str) -> bool:
    return ":" in addr


def _ip_header(src: str, dst: str, proto: int, payload_len: int, ttl: int = 64) -> bytes:
    if is_v6(src) != is_v6(dst):
        raise ValueError("source and destination must both be IPv4 or both IPv6")
    if is_v6(src):
        return struct.pack("!IHBB", 6 << 28, payload_len, proto, ttl) + \
            socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
    total = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    if is_v6(src):
        return (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
                + struct.pack("!I3xB", length, proto))
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


def build_icmp(src: str, dst: str, icmp_type: int | None = None, code: int = 0, payload: bytes = b"ping",
               rest: bytes | None = None) -> bytes:
    """ICMP (IPv4) or ICMPv6 message. `icmp_type` defaults to an echo request of the
    right version; `rest` replaces the 4-byte identifier/sequence word (errors use 0)."""
    v6 = is_v6(src)
    proto = PROTO_ICMPV6 if v6 else PROTO_ICMP
    if icmp_type is None:
        icmp_type = ECHO[6 if v6 else 4][0]
    msg = struct.pack("!BBH", icmp_type, code, 0) + (rest if rest is not None else struct.pack("!HH", 1, 1)) + payload
    pseudo = _pseudo(src, dst, proto, len(msg)) if v6 else b""      # ICMPv6 checksums the pseudo-header too
    msg = msg[:2] + struct.pack("!H", checksum(pseudo + msg)) + msg[4:]
    return _ip_header(src, dst, proto, len(msg)) + msg


def reject_reply(pkt: Packet, raw: bytes) -> tuple[bytes, str] | None:
    """The reply a REJECT rule sends back to the sender, as a host stack would:
    a TCP RST for TCP, an ICMP 'port unreachable' for UDP, 'administratively
    prohibited' for a ping. Errors are never answered (no RST to a RST, no ICMP
    error about an ICMP error), so two firewalls can't ping-pong. `raw` is the
    start of the offending packet, quoted in ICMP errors."""
    src, dst, v6 = pkt.dst_ip, pkt.src_ip, pkt.version == 6
    if pkt.protocol == PROTO_TCP:
        if pkt.has_flag(RST):
            return None
        if pkt.has_flag(ACK):
            return build_tcp(src, dst, pkt.dst_port, pkt.src_port, RST, seq=pkt.ack), "TCP RST"
        used = pkt.payload_len + pkt.has_flag(SYN) + pkt.has_flag(FIN)
        return build_tcp(src, dst, pkt.dst_port, pkt.src_port, RST | ACK,
                         ack=(pkt.seq + used) & 0xFFFFFFFF), "TCP RST"
    quote = raw[:48] if v6 else raw[:pkt.header_len + 8]
    if pkt.protocol == PROTO_UDP:
        t, c = (1, 4) if v6 else (3, 3)
        return build_icmp(src, dst, t, c, quote, rest=b"\0\0\0\0"), "ICMP port unreachable"
    if pkt.is_echo_request:
        t, c = (1, 1) if v6 else (3, 13)
        return build_icmp(src, dst, t, c, quote, rest=b"\0\0\0\0"), "ICMP administratively prohibited"
    return None


# --------------------------------------------------------------- dissection
def _f(name, offset, length, value, note=""):
    return {"name": name, "offset": offset, "length": length, "value": value, "note": note}


def dissect(data: bytes) -> list[dict]:
    """Break the kept header bytes into labelled fields, layer by layer, with the
    byte offset and length of each (bit fields share their byte). Used by the
    dashboard's packet inspector; returns what can be decoded from `data`."""
    layers = []
    if len(data) >= 40 and data[0] >> 4 == 6:
        return _dissect_v6(data)
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
    return layers + _dissect_transport(data[ihl:], ihl, proto)


def _dissect_v6(data: bytes) -> list[dict]:
    vtf, plen, nxt, hop = struct.unpack("!IHBB", data[:8])
    names = {0: "hop-by-hop options", 43: "routing", 44: "fragment", 51: "authentication", 60: "destination options"}
    layers = [{"layer": "IPv6", "offset": 0, "length": 40, "fields": [
        _f("Version", 0, 1, 6, "upper 4 bits"),
        _f("Traffic class", 0, 2, f"0x{(vtf >> 20) & 0xFF:02x}"),
        _f("Flow label", 1, 3, f"0x{vtf & 0xFFFFF:05x}"),
        _f("Payload length", 4, 2, plen, "bytes after this 40-byte header"),
        _f("Next header", 6, 1, f"{nxt} ({PROTO_NAMES.get(nxt) or names.get(nxt, 'other')})"),
        _f("Hop limit", 7, 1, hop, "IPv6's TTL: hops left"),
        _f("Source address", 8, 16, socket.inet_ntop(socket.AF_INET6, data[8:24])),
        _f("Destination address", 24, 16, socket.inet_ntop(socket.AF_INET6, data[24:40])),
    ]}]
    off = 40
    while nxt in _V6_EXT and len(data) >= off + 8:
        size = 8 if nxt == 44 else (data[off + 1] + 2) * 4 if nxt == 51 else (data[off + 1] + 1) * 8
        layers.append({"layer": f"IPv6 {names[nxt]}", "offset": off, "length": size, "fields": [
            _f("Next header", off, 1, f"{data[off]} ({PROTO_NAMES.get(data[off]) or names.get(data[off], 'other')})"),
            _f("Length", off + 1, 1, size, "bytes")]})
        nxt, off = data[off], off + size
    return layers + _dissect_transport(data[off:], off, nxt)


def _dissect_transport(seg: bytes, o: int, proto: int) -> list[dict]:
    layers = []
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
    elif proto in (PROTO_ICMP, PROTO_ICMPV6) and len(seg) >= 4:
        t, c, cs = struct.unpack("!BBH", seg[:4])
        kinds = ICMP_KINDS[6 if proto == PROTO_ICMPV6 else 4]
        fields = [_f("Type", o, 1, f"{t} ({kinds.get(t, 'other')})"), _f("Code", o + 1, 1, c),
                  _f("Checksum", o + 2, 2, f"0x{cs:04x}")]
        if t in (0, 8, 128, 129) and len(seg) >= 8:
            ident, sq = struct.unpack("!HH", seg[4:8])
            fields += [_f("Identifier", o + 4, 2, ident), _f("Sequence", o + 6, 2, sq)]
        layers.append({"layer": "ICMPv6" if proto == PROTO_ICMPV6 else "ICMP", "offset": o, "length": len(fields) > 3 and 8 or 4, "fields": fields})
    return layers
