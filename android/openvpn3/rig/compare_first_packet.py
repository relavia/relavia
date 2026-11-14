#!/usr/bin/env python3
"""First-packet byte comparison for the OpenVPN 3 loopback rig.

Reads two tcpdump captures of OpenVPN/TCP sessions taken on
loopback against the same server port — one from the
production OpenVPN 3 core (via Ovpn3LoopbackRig), one from a
known-good reference client (desktop OpenVPN 2.x) — and
decodes the first client-to-server control packet of each:

    [2-byte length][opcode|key-id][8-byte local session id]
    [ack array: 1-byte count, count x 4-byte packet ids,
     8-byte remote session id only when count > 0]
    [4-byte packet id][message-specific bytes ...]

For an initial HARD_RESET the ack array is empty and the
packet id is 0, so the whole first packet is normally
2+1+8+1+4 = 16 bytes on the wire. Any drift in opcode byte,
length, or trailing bytes between the two clients is printed
as a byte-by-byte diff. A first packet the server silently
drops would have to differ somewhere in these bytes (or in
how they are segmented across TCP segments, which is also
reported).

Usage:
    compare_first_packet.py CORE.pcap REFERENCE.pcap [PORT]

Either input may also be a raw client-to-server stream dump
(as written by byte_relay.py) instead of a pcap; the format
is detected from the pcap magic. Exit code 0 when both first
packets were extracted (identical or not — the diff IS the
output); 2 when extraction fails. Stdlib only.
"""

import struct
import sys

# Opcode numbering per the pinned core's openvpn/ssl/proto.hpp
# (this generation of the protocol renumbered the opcodes:
# CONTROL_V1 is 4, not 3).
OPCODES = {
    1: "CONTROL_HARD_RESET_CLIENT_V1",   # obsolete
    2: "CONTROL_HARD_RESET_SERVER_V1",   # obsolete
    4: "CONTROL_V1",
    5: "ACK_V1",
    6: "DATA_V1",
    7: "CONTROL_HARD_RESET_CLIENT_V2",
    8: "CONTROL_HARD_RESET_SERVER_V2",
    9: "DATA_V2",
    10: "CONTROL_HARD_RESET_CLIENT_V3",
}


def read_pcap(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise ValueError("short pcap")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = ">"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = "<"
    else:
        raise ValueError("unknown pcap magic %r" % magic)
    _, _, _, _, _, _, linktype = struct.unpack(endian + "IHHiIII", data[:24])
    off = 24
    packets = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        packets.append((ts_sec + ts_usec / 1e6, data[off:off + caplen]))
        off += caplen
    return linktype, packets


def ip_tcp_payload(linktype, frame):
    """Return (src_ip, src_port, dst_ip, dst_port, seq, payload) or None."""
    if linktype == 1:        # Ethernet
        if len(frame) < 14 or frame[12:14] != b"\x08\x00":
            return None
        ip = frame[14:]
    elif linktype == 113:    # Linux cooked (SLL)
        if len(frame) < 16 or frame[14:16] != b"\x08\x00":
            return None
        ip = frame[16:]
    elif linktype == 276:    # Linux cooked v2
        if len(frame) < 20 or frame[0:2] != b"\x08\x00":
            return None
        ip = frame[20:]
    else:                    # assume raw IP
        ip = frame
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0F) * 4
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack(">HHI", tcp[:8])
    doff = (tcp[12] >> 4) * 4
    return src, sport, dst, dport, seq, tcp[doff:]


def first_client_packet(path, server_port):
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        # Raw stream dump (byte_relay.py): the file IS the
        # client-to-server byte stream head.
        with open(path, "rb") as fh:
            return fh.read(), []
    linktype, packets = read_pcap(path)
    # First pass: learn the client port from the first payload
    # segment towards the server port, then reassemble that
    # flow's client-to-server byte stream in sequence order.
    segments = []
    client = None
    for ts, frame in packets:
        parsed = ip_tcp_payload(linktype, frame)
        if parsed is None:
            continue
        src, sport, dst, dport, seq, payload = parsed
        if dport == server_port and payload:
            if client is None:
                client = (src, sport)
            if (src, sport) == client:
                segments.append((seq, ts, payload))
    if not segments:
        raise ValueError("no client-to-server payload found in %s" % path)
    segments.sort()
    stream = bytearray()
    seg_sizes = []
    base = segments[0][0]
    for seq, ts, payload in segments:
        rel = seq - base
        if rel < 0:
            continue
        if rel > len(stream):
            break  # gap: only the contiguous head is meaningful here
        if rel + len(payload) > len(stream):
            stream.extend(payload[len(stream) - rel:])
            seg_sizes.append(len(payload))
        if len(stream) >= 18:
            break
    return bytes(stream), seg_sizes


def decode(stream):
    if len(stream) < 16:
        raise ValueError("stream too short: %d bytes" % len(stream))
    (length,) = struct.unpack(">H", stream[:2])
    packet = stream[2:2 + length]
    first = packet[0]
    opcode, key_id = first >> 3, first & 0x07
    session_id = packet[1:9]
    ack_count = packet[9]
    pos = 10
    ack_ids = []
    for _ in range(ack_count):
        (pid,) = struct.unpack(">I", packet[pos:pos + 4])
        ack_ids.append(pid)
        pos += 4
    remote_session = None
    if ack_count > 0:
        remote_session = packet[pos:pos + 8]
        pos += 8
    (packet_id,) = struct.unpack(">I", packet[pos:pos + 4])
    pos += 4
    rest = packet[pos:]
    return {
        "tcp_payload_bytes": length + 2,
        "packet_bytes": length,
        "first_byte": first,
        "opcode": OPCODES.get(opcode, "UNKNOWN_%d" % opcode),
        "opcode_num": opcode,
        "key_id": key_id,
        "session_id": session_id.hex(),
        "ack_count": ack_count,
        "ack_ids": ack_ids,
        "remote_session_id": remote_session.hex() if remote_session else None,
        "packet_id": packet_id,
        "trailing_after_header": rest.hex(),
        "raw": stream[:2 + length],
    }


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    port = int(argv[3]) if len(argv) > 3 else 1194
    try:
        core_stream, core_segs = first_client_packet(argv[1], port)
        ref_stream, ref_segs = first_client_packet(argv[2], port)
        core = decode(core_stream)
        ref = decode(ref_stream)
    except ValueError as exc:
        print("COMPARE_ERROR=%s" % exc)
        return 2

    print("=== production core (%s) ===" % argv[1])
    for key in ("tcp_payload_bytes", "packet_bytes", "first_byte", "opcode",
                "key_id", "session_id", "ack_count", "packet_id",
                "trailing_after_header"):
        print("CORE_%s=%s" % (key.upper(), core[key]))
    print("CORE_FIRST_SEGMENTS=%s" % ",".join(str(s) for s in core_segs))
    print("CORE_RAW=%s" % core["raw"].hex())
    print("=== reference client (%s) ===" % argv[2])
    for key in ("tcp_payload_bytes", "packet_bytes", "first_byte", "opcode",
                "key_id", "session_id", "ack_count", "packet_id",
                "trailing_after_header"):
        print("REF_%s=%s" % (key.upper(), ref[key]))
    print("REF_FIRST_SEGMENTS=%s" % ",".join(str(s) for s in ref_segs))
    print("REF_RAW=%s" % ref["raw"].hex())

    # Byte diff ignoring the random session id (bytes 3..10 of
    # the raw stream: 2 length + 1 opcode + session id start).
    a, b = core["raw"], ref["raw"]
    diffs = []
    for i in range(max(len(a), len(b))):
        av = a[i] if i < len(a) else None
        bv = b[i] if i < len(b) else None
        if av != bv and not (3 <= i < 11):
            diffs.append((i, av, bv))
    print("DIFF_BYTES_EXCLUDING_SESSION_ID=%s" % (
        ",".join("%d:%s!=%s" % (i,
                                "-" if av is None else "%02x" % av,
                                "-" if bv is None else "%02x" % bv)
                 for i, av, bv in diffs) if diffs else "none"))
    identical = (not diffs and core["opcode_num"] == ref["opcode_num"]
                 and core["packet_bytes"] == ref["packet_bytes"])
    print("FIRST_PACKET_IDENTICAL_EXCLUDING_SESSION_ID=%d" % (1 if identical else 0))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
