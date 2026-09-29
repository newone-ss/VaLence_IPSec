# tests/test_phase5_pcap.py
import struct

from tunneltwin.capture.pcap import (
    ETH_P_IPV4,
    LINKTYPE_ETHERNET,
    RawPacket,
    decode_ip,
)


def _eth_ipv4_udp(payload: bytes, sport=500, dport=500) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total,
        1,
        0,
        64,
        17,
        0,
        bytes([10, 0, 0, 1]),
        bytes([10, 0, 0, 2]),
    )
    eth = bytes(12) + struct.pack(">H", ETH_P_IPV4)
    return eth + ip + udp


def test_decode_ipv4_udp_roundtrip():
    raw = RawPacket(ts=1.0, linktype=LINKTYPE_ETHERNET, data=_eth_ipv4_udp(b"hi"))
    ip = decode_ip(raw)
    assert ip is not None
    assert ip.src == "10.0.0.1" and ip.dst == "10.0.0.2"
    assert ip.src_port == 500 and ip.dst_port == 500
    assert ip.payload == b"hi"


def test_non_udp_ignored_by_iter_ike_contract():
    raw = RawPacket(ts=1.0, linktype=LINKTYPE_ETHERNET, data=_eth_ipv4_udp(b"x", 1234, 1234))
    ip = decode_ip(raw)
    assert ip is not None and ip.src_port == 1234
