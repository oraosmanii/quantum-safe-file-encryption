# Interoperability results (RQ4)

**Question.** Can messages encrypted with GnuPG's post-quantum mode be decrypted by the RFC 9980 implementations Sequoia-PGP and GopenPGP, and the other way round? If not, where does it fail?

**Answer.** No, not in either direction. Sequoia and GopenPGP interoperate with each other in post-quantum mode, and each tool works with itself. Between GnuPG 2.5.22 and either of the other two, every post-quantum pair fails, and it fails before any ciphertext exists:
- **GnuPG → Sequoia / GopenPGP:** GnuPG cannot import their v6 certificates.
- **Sequoia / GopenPGP → GnuPG:** neither finds a usable encryption key in GnuPG's certificate.

With classical keys, all 9 directed pairs work. That is the positive control: it shows that the harness and the adapters are correct.

## Setup

| | |
|---|---|
| Tools | GnuPG `gpg (GnuPG) 2.5.22`, Sequoia `sq 1.4.0-pqc.1` (sequoia-openpgp 2.2.0-pqc.1, OpenSSL 3.5.7), GopenPGP `gopenpgp v3.4.1-proton` (through `interop/gopenpgp-cli`) |
| Classical keys | gpg: `--quick-gen-key … future-default` (Ed25519 + cv25519). `sq`: `--profile rfc4880 --cipher-suite cv25519`. GopenPGP: the library's default profile, a v4 key |
| PQC keys | gpg: Ed25519 primary + `ky768_cv25519` subkey, as in the benchmark (`pqc` shortcut not used). `sq`: `--profile rfc9580 --cipher-suite mldsa65-ed25519`. GopenPGP: the library's PQC profile (ML-DSA-65+Ed25519, ML-KEM-768+X25519) |
| Pairs | every directed pair of the 3 tools, including each tool with itself: 9 pairs × 2 key types |
| Repeats | 3, each with fresh keys, fresh keyrings, and a fresh 100 KiB random input |
| Stages | `keygen` (decryptor) → `import` (encryptor imports the decryptor's cert) → `encrypt` → `decrypt` → SHA-256 check. The runner stops at the first failed stage and records its exit code and complete stderr |
| Run | 2026-10-30, 16:39 UTC, on the measurement machine, with `make interop` |

Raw data: `matrix.csv` (54 rows), `packets.csv`, and the packet dumps in `dumps/`. Generated tables: `tables/interop_matrix.tex`, `tables/interop_packets.tex`.

## Results

All 3 repeats agree in every cell (stage, result, exit code).

**Classical keys:** 9 of 9 pairs pass.

**Post-quantum keys** (rows encrypt, columns decrypt):

| encryptor ↓ / decryptor → | gpg | sq | gopenpgp |
|---|---|---|---|
| **gpg** | pass | fail: import (exit 2) | fail: import (exit 2) |
| **sq** | fail: encrypt (exit 1) | pass | pass |
| **gopenpgp** | fail: encrypt (exit 1) | pass | pass |

### The failures

**gpg cannot import a v6 certificate** (gpg → sq, gpg → gopenpgp). The certificates of `sq` and GopenPGP are v6 keys. GnuPG reads every packet of them as an unknown version and imports nothing:

```text
gpg: packet(6) with unknown version 6
gpg: read_block: read error: Invalid packet
gpg: import from '.../key-sq/sq-pqc.pub.pgp' failed: Invalid keyring
gpg: Total number processed: 0
```

The error is the same for GopenPGP's certificate.

**sq and GopenPGP find no encryption key in GnuPG's certificate** (sq → gpg, gopenpgp → gpg). Both tools import the certificate without error. But they cannot read its post-quantum subkey, so the certificate has no key they can encrypt to:

```text
sq:       Error: Cert 4A766688771758EF7C7DA32078BF7DAAD2F0E19D, Interop Test
          <interop-gpg-pqc@example.invalid> (UNAUTHENTICATED) has no encryption-capable keys
gopenpgp: encrypt: gopenpgp: error in encrypting asymmetrically: openpgp: key selection for
          primary key 78BF7DAAD2F0E19D: no encryption key: no encryption-capable key found
          (no key flags or invalid algorithm)
```

(Repeat 1. Lines are wrapped here. Both name the Ed25519 primary key of GnuPG's certificate, the same key shown in `dumps/repeat-1_gpg_cert_gpg.txt`.)

The full stderr of every failing cell is in `matrix.csv`, column `error_message`.

## Why: the packet formats differ

From the packet dumps (`packets.csv`, `tables/interop_packets.tex`), identical in all 3 repeats:

| producer | encryption key packet | PK algorithm ID | PKESK version | encrypted data |
|---|---|---|---|---|
| gpg | v5 subkey (on a v4 Ed25519 primary) | 8 (`ky768_cv25519`) | 3 | AEAD packet, tag 20 (OCB) |
| sq | v6 | 35 (ML-KEM-768+X25519) | 6 | SEIPD v2 (AES-256, OCB) |
| gopenpgp | v6 | 35 (ML-KEM-768+X25519) | 3 | SEIPD v1 |

- **GnuPG and the other two use different algorithm IDs** for the same ML-KEM-768 + X25519 combination: 8 in GnuPG, 35 in Sequoia and GopenPGP, which `sq packet dump` names "ML-KEM-768+X25519". They also use different key packet versions: GnuPG puts the post-quantum subkey in a **v5** key packet, the others use **v6**.
- **Each side rejects the other's key packet.** `gpg --list-packets` reports every packet of a v6 certificate as "unknown version". `sq packet dump` reports GnuPG's v5 subkey as `Unknown or Unsupported Packet … Malformed packet: unknown version`. That is why `sq` sees GnuPG's certificate as having only the Ed25519 primary key, which cannot encrypt.
- **The message formats would not match either.** GnuPG's encrypted data uses the AEAD packet (tag 20). `sq` writes SEIPD v2 with a v6 PKESK. GopenPGP writes SEIPD v1 with a v3 PKESK, even for a v6 key. In the matrix, `sq` and GopenPGP decrypt each other's messages in both directions. With GnuPG it never gets that far: every cross pair fails at import or encrypt, so no cross-implementation ciphertext was ever produced.

So the incompatibility is in the key format, before any post-quantum cryptography runs. GnuPG 2.5.22 does not implement the RFC 9980 encoding that Sequoia and GopenPGP use, and they do not implement GnuPG's.

## Reading the dumps

- `dumps/repeat-<r>_<producer>_<object>_<dumper>.txt`: the producer's PQC certificate or ciphertext, dumped with `gpg --list-packets` or `sq packet dump`. Each file starts with the command and its exit code. The certificates and ciphertexts come from the same repeat's scratch directory.
- A ciphertext dump made with `sq` ends with "No key to decrypt message", because the dumper has no secret key. That is expected and not an error.
- When gpg dumps a v6 message, only the first two packets mean anything (PKESK v6 and SEIPD v2, both "unknown version"). gpg then reads the encrypted bytes as packets, so the rest of the file is noise. Its length depends on the random ciphertext, which is why `repeat-3_sq_ciphertext_gpg.txt` is much larger than the same file in repeats 1 and 2.
- An empty field in `packets.csv` means the dumper did not print that field. It does not mean the packet lacks it.

## Notes on the run

- The run uses a rebuild of the `pqc-bench` image that differs from the benchmark's only in the GopenPGP CLI wrapper (`interop/gopenpgp-cli`). Every tool version is the pinned one and is recorded in each row of `matrix.csv`.
- The matrix was run twice on 2026-10-30. In the first run, the `sq` version column was empty because of a bug in `interop/adapters.py`: the version check took the first line of an output that started with an empty line. After the fix, `make interop` was run again as a whole, and its output replaces the first run's. Both runs gave the same stage, result, and exit code in all 54 cells.

## Reproduce

```bash
make image && make smoke
```
```bash
make interop
```

This writes `matrix.csv`, `packets.csv`, `dumps/`, and both tables, and takes under a minute.
