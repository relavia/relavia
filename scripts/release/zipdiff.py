#!/usr/bin/env python3
"""zipdiff.py — entry-level diff of two ZIP/APK files.

Used by scripts/release/repro-check.sh when two builds of an APK
do not hash identically: it localizes the difference to
  - entries present in only one file,
  - entries whose decompressed content differs,
  - entries whose content is identical but whose ZIP metadata
    (timestamp, compression, attributes) differs,
so the report can distinguish "same content, different container
metadata" from a real content difference.

Usage: zipdiff.py <file-a> <file-b>
Exit code: 0 if entry contents are all equal, 1 otherwise.
"""
import hashlib
import sys
import zipfile


def load(path):
    entries = {}
    order = []
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            data = z.read(info.filename)
            entries[info.filename] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "date_time": info.date_time,
                "compress_type": info.compress_type,
                "external_attr": info.external_attr,
                "crc": info.CRC,
            }
            order.append(info.filename)
    return entries, order


def main():
    if len(sys.argv) != 3:
        print("usage: zipdiff.py <file-a> <file-b>", file=sys.stderr)
        return 2
    a, order_a = load(sys.argv[1])
    b, order_b = load(sys.argv[2])
    content_diff = False

    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    for name in only_a:
        print(f"ONLY IN A: {name}")
        content_diff = True
    for name in only_b:
        print(f"ONLY IN B: {name}")
        content_diff = True

    meta_only = []
    for name in sorted(set(a) & set(b)):
        ea, eb = a[name], b[name]
        if ea["sha256"] != eb["sha256"]:
            print(f"CONTENT DIFFERS: {name} (A: {ea['size']} bytes, sha256 {ea['sha256'][:16]}…; "
                  f"B: {eb['size']} bytes, sha256 {eb['sha256'][:16]}…)")
            content_diff = True
        elif (ea["date_time"] != eb["date_time"]
              or ea["compress_type"] != eb["compress_type"]
              or ea["external_attr"] != eb["external_attr"]):
            meta_only.append(name)
    for name in meta_only:
        print(f"METADATA ONLY: {name} (A time={a[name]['date_time']} type={a[name]['compress_type']} "
              f"attr={a[name]['external_attr']:#x}; B time={b[name]['date_time']} "
              f"type={b[name]['compress_type']} attr={b[name]['external_attr']:#x})")
    if order_a != order_b and set(order_a) == set(order_b):
        print("ENTRY ORDER DIFFERS (same entry set, different order)")
    if not content_diff and not meta_only and order_a == order_b:
        print("entries identical (content, metadata, order) — "
              "the difference must be outside the ZIP entries "
              "(e.g. APK signing block or ZIP-level fields)")
    return 1 if content_diff else 0


if __name__ == "__main__":
    sys.exit(main())
