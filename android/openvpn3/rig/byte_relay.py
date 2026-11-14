#!/usr/bin/env python3
"""Byte-logging TCP relay for the OpenVPN 3 loopback rig.

The rig's first-packet comparison needs the exact bytes a
client puts on the wire. Packet capture (tcpdump/AF_PACKET)
is not available in every sandbox/CI network — the reference
sandbox refuses it outright (EPERM on loopback even as
root) — so the rig captures at a relay instead: the client
connects to this relay, the relay forwards to the real
server, and the first bytes of each direction are recorded
verbatim. For comparing the first control packet that is
exactly the evidence needed; the one thing a relay cannot
show is TCP segmentation, so the sizes of the first recv()
chunks on the client side are logged as an approximation
and labelled as such (on loopback a single small write
arrives as a single chunk).

Usage:
    byte_relay.py LISTEN_PORT TARGET_PORT OUT_PREFIX

Writes OUT_PREFIX.c2s.bin / OUT_PREFIX.s2c.bin (first 4096
bytes of each direction) and prints C2S_CHUNKS=... with the
client-side recv chunk sizes. Runs until killed; one
connection at a time is all the rig needs, but sequential
connections are accepted. Stdlib only.
"""

import socket
import sys
import threading

CAP = 4096


def pump(src, dst, store, chunks=None):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if chunks is not None and len(chunks) < 8:
                chunks.append(len(data))
            if len(store) < CAP:
                store += data[:CAP - len(store)]
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    listen_port, target_port, prefix = int(argv[1]), int(argv[2]), argv[3]
    c2s = bytearray()
    s2c = bytearray()
    chunks = []

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", listen_port))
    server.listen(4)
    print("RELAY_LISTENING=%d->%d" % (listen_port, target_port), flush=True)
    while True:
        client, _ = server.accept()
        target = socket.create_connection(("127.0.0.1", target_port))
        up = threading.Thread(target=pump, args=(client, target, c2s, chunks),
                              daemon=True)
        down = threading.Thread(target=pump, args=(target, client, s2c),
                                daemon=True)
        up.start()
        down.start()
        up.join()
        down.join()
        with open(prefix + ".c2s.bin", "wb") as fh:
            fh.write(bytes(c2s))
        with open(prefix + ".s2c.bin", "wb") as fh:
            fh.write(bytes(s2c))
        print("C2S_CHUNKS=%s" % ",".join(str(n) for n in chunks), flush=True)
        print("C2S_BYTES=%d S2C_BYTES=%d" % (len(c2s), len(s2c)), flush=True)
        client.close()
        target.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
