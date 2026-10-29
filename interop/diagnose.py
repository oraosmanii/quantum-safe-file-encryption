#!/usr/bin/env python3
"""Dump packet evidence for failing PQC cells in matrix.csv."""
from __future__ import annotations

import argparse
import base64
import csv
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["producer", "key_type", "object", "dumped_with", "key_version", "pk_algo_id",
          "pkesk_version", "seipd_version", "dump_file"]


def run(args, timeout=60):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, str(exc)


def _packet_stream(data):
    """Yield (tag, body) from new- and old-format OpenPGP packet headers."""
    if data.startswith(b"-----BEGIN PGP "):
        lines = data.decode("ascii", "ignore").splitlines()
        start = next((i + 1 for i, line in enumerate(lines) if not line.strip()), len(lines))
        encoded = []
        for line in lines[start:]:
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("-----END"):
                break
            encoded.append(line)
        data = base64.b64decode("".join(encoded))
    pos = 0
    while pos < len(data):
        ctb = data[pos]
        if not ctb & 0x80:
            break
        pos += 1
        if ctb & 0x40:
            tag = ctb & 0x3f
            if pos >= len(data):
                break
            first = data[pos]
            pos += 1
            if first < 192:
                length = first
                body = data[pos:pos + length]
                pos += length
            elif first < 224:
                if pos >= len(data):
                    break
                length = ((first - 192) << 8) + data[pos] + 192
                pos += 1
                body = data[pos:pos + length]
                pos += length
            elif first == 255:
                if pos + 4 > len(data):
                    break
                length = int.from_bytes(data[pos:pos + 4], "big")
                pos += 4
                body = data[pos:pos + length]
                pos += length
            else:
                chunks = []
                length = 1 << (first & 0x1f)
                while True:
                    chunks.append(data[pos:pos + length])
                    pos += length
                    if pos >= len(data):
                        break
                    n = data[pos]
                    pos += 1
                    if n < 192:
                        length = n
                    elif n < 224:
                        if pos >= len(data):
                            break
                        length = ((n - 192) << 8) + data[pos] + 192
                        pos += 1
                    elif n == 255:
                        if pos + 4 > len(data):
                            break
                        length = int.from_bytes(data[pos:pos + 4], "big")
                        pos += 4
                    else:
                        length = 1 << (n & 0x1f)
                        continue
                    chunks.append(data[pos:pos + length])
                    pos += length
                    break
                body = b"".join(chunks)
        else:
            tag = (ctb >> 2) & 0x0f
            length_type = ctb & 0x03
            width = (1, 2, 4, 0)[length_type]
            if width == 0:
                body = data[pos:]
                pos = len(data)
            else:
                if pos + width > len(data):
                    break
                length = int.from_bytes(data[pos:pos + width], "big")
                pos += width
                body = data[pos:pos + length]
                pos += length
        yield tag, body


def parse_cert(data):
    subkeys = [body for tag, body in _packet_stream(data) if tag == 14 and len(body) >= 6]
    if not subkeys:
        return "", ""
    packet = subkeys[-1]  # The encryption subkey is the last subkey in our generated certs.
    version, algo = packet[0], packet[5]
    return f"v{version}", str(algo)


def parse_cipher(data):
    pkesk_version = pk_algo = data_packet = ""
    for tag, body in _packet_stream(data):
        if tag == 1 and body:
            version = body[0]
            pkesk_version = str(version)
            if version == 3 and len(body) >= 10:
                pk_algo = str(body[9])
            elif version == 6 and len(body) >= 3 + body[1]:
                pk_algo = str(body[2 + body[1]])
        elif tag == 18 and body:
            data_packet = str(body[0])
        elif tag == 20:
            # LibrePGP AEAD Encrypted Data is tag 20, not an RFC 9580 SEIPD packet.
            data_packet = "tag20/AEAD"
    return pkesk_version, pk_algo, data_packet


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--matrix", type=Path, default=ROOT / "results" / "interop" / "matrix.csv")
    ap.add_argument("--work-root", type=Path, default=ROOT / "tmp" / "interop")
    ap.add_argument("--output", type=Path, default=ROOT / "results" / "interop" / "packets.csv")
    ap.add_argument("--dumps", type=Path, default=ROOT / "results" / "interop" / "dumps")
    args = ap.parse_args()
    args.matrix = args.matrix.resolve()
    args.work_root = args.work_root.resolve()
    args.output = args.output.resolve()
    args.dumps = args.dumps.resolve()
    if not args.matrix.exists():
        ap.error(f"matrix not found: {args.matrix}")
    with args.matrix.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    pqc_rows = [r for r in rows if r["key_type"] == "pqc"]
    args.dumps.mkdir(parents=True, exist_ok=True)
    packet_rows, seen = [], set()
    # Dump PQC certs for every recipient and one emitted ciphertext per producer.
    # A failed import/encrypt cell has no ciphertext, so retain packet evidence from
    # successful cells by the same producer to explain the incompatible formats.
    for r in pqc_rows:
        repeat, enc, dec = r["repeat"], r["encryptor"], r["decryptor"]
        base = args.work_root / f"repeat-{repeat}" / "pqc"
        cert = base / f"key-{dec}" / f"{dec}-pqc.pub.pgp"
        cipher = base / f"{enc}-to-{dec}" / "ciphertext.pgp"
        for obj, producer, path in (("cert", dec, cert), ("ciphertext", enc, cipher)):
            if (producer, obj, repeat) in seen or not path.is_file() or path.stat().st_size == 0:
                continue
            seen.add((producer, obj, repeat))
            for dumper, cmd in (("gpg", ["gpg", "--batch", "--list-packets", str(path)]),
                                ("sq", ["sq", "packet", "dump", str(path)])):
                rc, output = run(cmd)
                dump_name = f"repeat-{repeat}_{producer}_{obj}_{dumper}.txt"
                dump_path = args.dumps / dump_name
                dump_path.write_text(f"command: {' '.join(cmd)}\nexit_code: {rc}\n\n{output or '[no textual output]'}", encoding="utf-8")
                raw = path.read_bytes()
                kv, algo = parse_cert(raw) if obj == "cert" else ("", "")
                pv, pa, sv = parse_cipher(raw) if obj == "ciphertext" else ("", "", "")
                packet_rows.append({"producer": producer, "key_type": "pqc", "object": obj,
                                    "dumped_with": dumper, "key_version": kv, "pk_algo_id": algo or pa,
                                    "pkesk_version": pv, "seipd_version": sv,
                                    "dump_file": str(dump_path.relative_to(ROOT)).replace("\\", "/")})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(packet_rows)
    print(f"wrote {len(packet_rows)} packet records from {len(pqc_rows)} PQC matrix rows")


if __name__ == "__main__":
    main()
