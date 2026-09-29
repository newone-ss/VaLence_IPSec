"""Dependency-free PCAP / PCAPNG ingestion for TunnelTwin.

Reads classic libpcap and the pcapng subset TunnelTwin needs (Section
Header, Interface Description, Enhanced Packet, Simple Packet blocks),
then decodes Ethernet / Linux SLL / raw-IP / BSD-loopback framing down
to IPv4/IPv6 and the transport payload.

No Scapy anywhere in this path. The IKE bytes produced here are handed
straight to :mod:`tunneltwin.ike.codec` -- the same parser the live probe
engine uses, so PCAP analysis and active scanning cannot drift apart.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100
ETH_P_QINQ = 0x88A8

IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ESP = 50
IPPROTO_AH = 51

_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
}

_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_SPB = 0x00000003
_PCAPNG_EPB = 0x00000006

_MAX_IPV6_EXT_HEADERS = 8


@dataclass(frozen=True)
class RawPacket:
    """One captured frame, still in its link-layer framing."""

    ts: float
    linktype: int
    data: bytes


@dataclass(frozen=True)
class IpPacket:
    """A decoded IPv4/IPv6 packet with its transport payload isolated."""

    ts: float
    src: str
    dst: str
    proto: int
    ip_total_len: int
    ip_header_len: int
    payload: bytes
    is_ipv6: bool
    src_port: int | None = None
    dst_port: int | None = None

    @property
    def flow_key(self) -> tuple[str, str, int, int | None, int | None]:
        return (self.src, self.dst, self.proto, self.src_port, self.dst_port)

    @property
    def conversation_key(self) -> tuple[str, str]:
        a, b = sorted((self.src, self.dst))
        return (a, b)


# --------------------------------------------------------------------------
# File readers
# --------------------------------------------------------------------------


def read_packets(path: str | Path) -> Iterator[RawPacket]:
    """Yield :class:`RawPacket` from a .pcap or .pcapng file."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        if len(head) < 4:
            return
        fh.seek(0)
        if head in _MAGICS:
            yield from _read_classic(fh)
        elif head == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(fh)
        else:
            raise ValueError(f"unrecognised capture magic {head!r} in {path}")


def _read_classic(fh: BinaryIO) -> Iterator[RawPacket]:
    magic = fh.read(4)
    endian, tsdiv = _MAGICS[magic]
    rest = fh.read(20)
    if len(rest) < 20:
        return
    _vmaj, _vmin, _tz, _sig, _snap, network = struct.unpack(endian + "HHiIII", rest)
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", rec)
        data = fh.read(incl)
        if len(data) < incl:
            return
        yield RawPacket(ts=ts_sec + ts_frac / tsdiv, linktype=network, data=data)


def _parse_if_tsresol(opts: bytes, endian: str, default: int) -> int:
    off = 0
    while off + 4 <= len(opts):
        code, length = struct.unpack(endian + "HH", opts[off : off + 4])
        if code == 0:
            break
        value = opts[off + 4 : off + 4 + length]
        if code == 9 and length == 1 and value:
            raw = value[0]
            if raw & 0x80:
                return -1  # base-2 resolution; caller falls back to default
            return int(raw)
        off += 4 + ((length + 3) // 4) * 4
    return default


def _read_pcapng(fh: BinaryIO) -> Iterator[RawPacket]:
    endian = "<"
    interfaces: list[tuple[int, int]] = []
    while True:
        pos = fh.tell()
        head = fh.read(8)
        if len(head) < 8:
            return
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            bom = fh.read(4)
            if len(bom) < 4:
                return
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                raise ValueError("bad pcapng byte-order magic")
            fh.seek(pos + 4)
            blen = struct.unpack(endian + "I", fh.read(4))[0]
            if blen < 12:
                return
            fh.seek(pos + blen)
            interfaces = []
            continue

        btype, blen = struct.unpack(endian + "II", head)
        if blen < 12:
            return
        body = fh.read(blen - 12)
        fh.read(4)  # trailing block length

        if btype == _PCAPNG_IDB and len(body) >= 8:
            linktype, _res, _snap = struct.unpack(endian + "HHI", body[:8])
            tsres = _parse_if_tsresol(body[8:], endian, 6)
            interfaces.append((linktype, tsres))

        elif btype == _PCAPNG_EPB and len(body) >= 20:
            iface_id, ts_hi, ts_lo, cap_len, _orig = struct.unpack(endian + "IIIII", body[:20])
            data = body[20 : 20 + cap_len]
            linktype, tsres = interfaces[iface_id] if iface_id < len(interfaces) else (LINKTYPE_ETHERNET, 6)
            ticks = (ts_hi << 32) | ts_lo
            divisor = float(10**tsres) if tsres >= 0 else float(2 ** (-tsres))
            yield RawPacket(ts=ticks / divisor, linktype=linktype, data=data)

        elif btype == _PCAPNG_SPB and len(body) >= 4 and interfaces:
            orig_len = struct.unpack(endian + "I", body[:4])[0]
            linktype, _ = interfaces[0]
            yield RawPacket(ts=0.0, linktype=linktype, data=body[4 : 4 + orig_len])


# --------------------------------------------------------------------------
# Link / network layer decode
# --------------------------------------------------------------------------


def decode_ip(pkt: RawPacket) -> IpPacket | None:
    """Decode one :class:`RawPacket` down to an :class:`IpPacket` or None."""
    data = pkt.data
    lt = pkt.linktype

    if lt == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack(">H", data[12:14])[0]
        off = 14
        while ethertype in (ETH_P_VLAN, ETH_P_QINQ) and len(data) >= off + 4:
            ethertype = struct.unpack(">H", data[off + 2 : off + 4])[0]
            off += 4
        return _dispatch_ip(data[off:], ethertype, pkt.ts)

    if lt == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        ethertype = struct.unpack(">H", data[14:16])[0]
        return _dispatch_ip(data[16:], ethertype, pkt.ts)

    if lt == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None
        ethertype = struct.unpack(">H", data[0:2])[0]
        return _dispatch_ip(data[20:], ethertype, pkt.ts)

    if lt in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not data:
            return None
        version = data[0] >> 4
        ethertype = ETH_P_IPV4 if version == 4 else ETH_P_IPV6
        return _dispatch_ip(data, ethertype, pkt.ts)

    if lt == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        fam_le = struct.unpack("<I", data[:4])[0]
        fam_be = struct.unpack(">I", data[:4])[0]
        if fam_le in (2, 4, 24) or fam_be in (2, 4, 24):
            return _dispatch_ip(data[4:], ETH_P_IPV4, pkt.ts)
        if fam_le in (10, 28, 30) or fam_be in (10, 28, 30):
            return _dispatch_ip(data[4:], ETH_P_IPV6, pkt.ts)
        return None

    return None


def _dispatch_ip(data: bytes, ethertype: int, ts: float) -> IpPacket | None:
    if ethertype == ETH_P_IPV4:
        return _parse_ipv4(data, ts)
    if ethertype == ETH_P_IPV6:
        return _parse_ipv6(data, ts)
    return None


def _parse_ipv4(data: bytes, ts: float) -> IpPacket | None:
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack(">H", data[2:4])[0]
    # Fragmented traffic: only the first fragment carries the transport header.
    frag_off = struct.unpack(">H", data[6:8])[0] & 0x1FFF
    if frag_off != 0:
        return None
    ttl = data[8]
    proto = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    end = min(total_len, len(data)) if total_len else len(data)
    body = data[ihl:end]
    return _finish_ip(ts, src, dst, proto, total_len or len(data), ihl, body, False, ttl)


def _parse_ipv6(data: bytes, ts: float) -> IpPacket | None:
    if len(data) < 40 or (data[0] >> 4) != 6:
        return None
    payload_len = struct.unpack(">H", data[4:6])[0]
    next_hdr = data[6]
    src = _fmt_ipv6(data[8:24])
    dst = _fmt_ipv6(data[24:40])
    off = 40
    total = 40 + payload_len if payload_len else len(data)
    end = min(total, len(data))

    walked = 0
    while walked < _MAX_IPV6_EXT_HEADERS:
        if next_hdr in (IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ESP, IPPROTO_AH):
            break
        if off + 2 > end:
            break
        if next_hdr == 44:  # Fragment header, fixed 8 bytes
            if off + 8 > end:
                break
            nh = data[off]
            frag_off = struct.unpack(">H", data[off + 2 : off + 4])[0] >> 3
            if frag_off != 0:
                return None
            next_hdr, off = nh, off + 8
        elif next_hdr in (0, 43, 60, 135):  # len = (hdr_ext_len + 1) * 8
            hlen = (data[off + 1] + 1) * 8
            if off + hlen > end:
                break
            next_hdr, off = data[off], off + hlen
        elif next_hdr == 51:  # AH: len = (hdr_ext_len + 2) * 4
            hlen = (data[off + 1] + 2) * 4
            if off + hlen > end:
                break
            next_hdr, off = data[off], off + hlen
        else:
            break
        walked += 1

    if next_hdr == 51:
        return IpPacket(ts, src, dst, IPPROTO_AH, total, off, data[off:end], True)
    return _finish_ip(ts, src, dst, next_hdr, total, off, data[off:end], True, data[7])


def _finish_ip(
    ts: float,
    src: str,
    dst: str,
    proto: int,
    total_len: int,
    hdr_len: int,
    body: bytes,
    is_ipv6: bool,
    _ttl: int,
) -> IpPacket:
    sport: int | None = None
    dport: int | None = None
    if proto in (IPPROTO_UDP, IPPROTO_TCP) and len(body) >= 4:
        sport, dport = struct.unpack(">HH", body[:4])
        if proto == IPPROTO_UDP and len(body) >= 8:
            udp_len = struct.unpack(">H", body[4:6])[0]
            payload = body[8 : max(8, udp_len)] if udp_len >= 8 else body[8:]
        elif proto == IPPROTO_TCP:
            data_off = (body[12] >> 4) * 4 if len(body) >= 13 else 20
            payload = body[data_off:] if data_off >= 20 else body[20:]
        else:
            payload = body[8:]
        return IpPacket(ts, src, dst, proto, total_len, hdr_len, payload, is_ipv6, sport, dport)
    return IpPacket(ts, src, dst, proto, total_len, hdr_len, body, is_ipv6)


def _fmt_ipv6(raw: bytes) -> str:
    groups = [struct.unpack(">H", raw[i : i + 2])[0] for i in range(0, 16, 2)]
    # RFC 5952-ish compression of the longest zero run
    best_start = best_len = cur_start = cur_len = -1
    for i, g in enumerate(groups):
        if g == 0:
            if cur_start < 0:
                cur_start, cur_len = i, 1
            else:
                cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_start = cur_len = -1
    if best_len < 2:
        return ":".join(f"{g:x}" for g in groups)
    head = ":".join(f"{g:x}" for g in groups[:best_start])
    tail = ":".join(f"{g:x}" for g in groups[best_start + best_len :])
    return f"{head}::{tail}"


# --------------------------------------------------------------------------
# Convenience iterators
# --------------------------------------------------------------------------


def iter_ip(path: str | Path) -> Iterator[IpPacket]:
    for raw in read_packets(path):
        ip = decode_ip(raw)
        if ip is not None:
            yield ip


def iter_esp(path: str | Path) -> Iterator[IpPacket]:
    for ip in iter_ip(path):
        if ip.proto == IPPROTO_ESP:
            yield ip


def iter_ike(path: str | Path) -> Iterator[IpPacket]:
    """Yield UDP/500 and UDP/4500 packets, stripping the non-ESP marker.

    Payload for port 4500 is rewritten in place so the caller never has to
    think about RFC 3948 framing.
    """
    for ip in iter_ip(path):
        if ip.proto != IPPROTO_UDP:
            continue
        if 500 not in (ip.src_port, ip.dst_port) and 4500 not in (
            ip.src_port,
            ip.dst_port,
        ):
            continue
        payload = ip.payload
        via_4500 = 4500 in (ip.src_port, ip.dst_port)
        if via_4500:
            if len(payload) < 4 or payload[:4] != b"\x00\x00\x00\x00":
                continue  # real ESP-in-UDP, not IKE
            payload = payload[4:]
        yield IpPacket(
            ip.ts,
            ip.src,
            ip.dst,
            ip.proto,
            ip.ip_total_len,
            ip.ip_header_len,
            payload,
            ip.is_ipv6,
            ip.src_port,
            ip.dst_port,
        )
