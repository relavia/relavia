# Shadowsocks test vectors

`vectors.json` is the frozen vector set for the self-developed
Shadowsocks engine, generated per
`docs/自研协议路线-01-shadowsocks-测试向量清单.md`. Every password,
PSK and salt in it is a **TEST-ONLY** value.

## Regeneration (must be byte-identical)

```sh
cd genvectors && go run .        # rewrites ../vectors.json
git diff ../vectors.json         # must be empty
```

A non-empty diff means the generator or an expectation changed.
Vector files are **append-only**: a changed expectation gets a
new vector ID with a supersedes note, never an in-place edit
(checklist rule F.2).

## Dual-source cross-checks (checklist rule F.1)

Every P0 expectation carries at least two independent sources,
recorded per vector in its `sources` field:

| Family | Source 1 | Source 2 |
| --- | --- | --- |
| EVP_BytesToKey (KDF-01/02/03/07) | SIP004 + generator | OpenSSL CLI (`crosscheck.py`) |
| HKDF-SHA1 (KDF-04) | SIP004 + generator | Python RFC 5869 implementation (`crosscheck.py`) |
| BLAKE3 subkey (KDF-05) | SIP022 + generator (zeebo/blake3) | lukechampine.com/blake3 (`xcheck/`) |
| AEAD primitives (AEAD-01/02) | published vectors (GCM spec test cases, RFC 8439 A.5) asserted inside the generator | the vetted Go libraries |
| Wire streams/packets (W17/W22) | SIP004/SIP022 + generator | shadowsocks-rust v1.25.0 and sing-box v1.14.4 live interop - enforced by the diffrig cross-decryption tests in `core/selfdev/diffrig`, which must pass for the set to count as verified |

Run the offline checks with:

```sh
python3 crosscheck.py vectors.json
cd xcheck && go run .
```

If any check disagrees, the affected vector is **frozen**: do
not edit the expectation to match; report the divergence and
adjudicate per the spec's G4 rule.

## Corrections

- 2026-11-23: W17-01..04 and W17-06 carry a `withdrawn` marker
  on `expected.responseStream` - the original response streams
  were generated with the request-direction model (address
  header + payload), but a 2017 TCP response has no address
  header. The original bytes stay in the file for audit; the
  corrected response streams are W17-21..24 and W17-26. See
  spec section 6 item 8 and checklist section G.
