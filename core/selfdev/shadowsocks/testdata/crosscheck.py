#!/usr/bin/env python3
"""Independent second source for the password-based KDF vectors.

- EVP_BytesToKey expectations (KDF-01/02/03/07) are recomputed by
  the OpenSSL CLI (`openssl enc -P -md md5 -nosalt`), OpenSSL being
  the reference implementation of EVP_BytesToKey.
- HKDF-SHA1 expectations (KDF-04) are recomputed here from
  RFC 5869 first principles with Python's hmac/hashlib - no
  Shadowsocks code involved.

Usage: python3 crosscheck.py [vectors.json]
Exits non-zero on the first disagreement; a disagreement freezes
the vector (checklist rule F.1) and must be reported, not edited
away.
"""

import hashlib
import hmac as hmac_mod
import json
import subprocess
import sys


def openssl_evp_key(password: bytes, key_len: int) -> bytes:
    cipher = {16: "aes-128-cbc", 32: "aes-256-cbc"}[key_len]
    out = subprocess.run(
        ["openssl", "enc", f"-{cipher}", "-k", password.decode("utf-8", "surrogateescape"),
         "-nosalt", "-md", "md5", "-P"],
        capture_output=True, text=True, check=True,
    ).stdout
    for line in out.splitlines():
        if line.startswith("key="):
            return bytes.fromhex(line[4:].strip())
    raise RuntimeError("openssl did not print a key:\n" + out)


def hkdf_sha1(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac_mod.new(salt, ikm, hashlib.sha1).digest()
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha1).digest()
        okm += t
        counter += 1
    return okm[:length]


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "vectors.json"
    with open(path) as f:
        vectors = json.load(f)["vectors"]
    checked = 0
    for v in vectors:
        if v["category"] != "kdf":
            continue
        inp, exp = v["inputs"], v["expected"]
        if "masterKey" in exp:
            pw = bytes.fromhex(inp["passwordHex"]) if "passwordHex" in inp else inp["password"].encode()
            got = openssl_evp_key(pw, inp["keyLen"])
            want = bytes.fromhex(exp["masterKey"])
            if got != want:
                print(f"MISMATCH {v['id']}: openssl={got.hex()} vectors.json={want.hex()}")
                return 1
            print(f"OK {v['id']} (OpenSSL EVP_BytesToKey agrees)")
            checked += 1
        elif "subkey" in exp and "masterKey" in inp:
            got = hkdf_sha1(bytes.fromhex(inp["masterKey"]), bytes.fromhex(inp["salt"]),
                            inp["info"].encode(), inp["keyLen"])
            want = bytes.fromhex(exp["subkey"])
            if got != want:
                print(f"MISMATCH {v['id']}: python-hkdf={got.hex()} vectors.json={want.hex()}")
                return 1
            print(f"OK {v['id']} (Python RFC 5869 HKDF-SHA1 agrees)")
            checked += 1
    print(f"crosscheck: {checked} KDF vectors verified")
    return 0 if checked else 1


if __name__ == "__main__":
    sys.exit(main())
