#!/usr/bin/env python3
"""Run the 3x3 OpenPGP interoperability matrix with fresh keys per repeat."""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import secrets
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import adapters

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "results" / "interop" / "matrix.csv"
FIELDS = ["timestamp_utc", "repeat", "encryptor", "decryptor", "key_type", "stage_reached",
          "result", "exit_code", "error_message", "encryptor_version", "decryptor_version"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=3, help="number of full runs (default: 3)")
    parser.add_argument("--work-root", type=Path, default=ROOT / "tmp" / "interop")
    parser.add_argument("--output", type=Path, default=CSV)
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.work_root.mkdir(parents=True, exist_ok=True)
    versions = {}
    for tool in adapters.TOOLS:
        versions[tool] = adapters.version(tool, args.work_root / "version-check")
    rows = []
    for repeat in range(1, args.repeat + 1):
        repeat_dir = args.work_root / f"repeat-{repeat}"
        # tmp/interop is scratch space. Remove only this repeat's previous scratch
        # directory so rerunning with the same --work-root cannot reuse stale keys,
        # keyrings, or ciphertexts.
        if repeat_dir.exists():
            shutil.rmtree(repeat_dir)
        repeat_dir.mkdir(parents=True, exist_ok=True)
        # Fresh 100 KiB random control file for each run; keys and homes are also fresh.
        plaintext = repeat_dir / "input.bin"
        plaintext.write_bytes(secrets.token_bytes(100 * 1024))
        expected = hashlib.sha256(plaintext.read_bytes()).hexdigest()
        for key_type in ("classical", "pqc"):
            keypairs = {}
            for decryptor in adapters.TOOLS:
                key_dir = repeat_dir / key_type / f"key-{decryptor}"
                try:
                    keypairs[decryptor] = adapters.keygen(decryptor, key_type, key_dir)
                except Exception as exc:
                    keypairs[decryptor] = (None, None, str(exc))
            for encryptor in adapters.TOOLS:
                for decryptor in adapters.TOOLS:
                    row = {"timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                           "repeat": repeat, "encryptor": encryptor, "decryptor": decryptor,
                           "key_type": key_type, "stage_reached": "done", "result": "pass",
                           "exit_code": 0, "error_message": "",
                           "encryptor_version": versions[encryptor], "decryptor_version": versions[decryptor]}
                    pair_dir = repeat_dir / key_type / f"{encryptor}-to-{decryptor}"
                    pair_dir.mkdir(parents=True, exist_ok=True)
                    pair = keypairs[decryptor]
                    if pair[0] is None:
                        row.update(stage_reached="keygen", result="fail", exit_code=1, error_message=pair[2])
                    else:
                        secret, cert = pair
                        steps = [("import", lambda: adapters.import_cert(encryptor, cert, pair_dir)),
                                 ("encrypt", lambda: adapters.encrypt(encryptor, cert, plaintext, pair_dir / "ciphertext.pgp", pair_dir)),
                                 ("decrypt", lambda: adapters.decrypt(decryptor, secret, pair_dir / "ciphertext.pgp", pair_dir / "decrypted.bin", pair_dir))]
                        for stage, call in steps:
                            ok, code, stderr, _duration = call()
                            if not ok:
                                row.update(stage_reached=stage, result="fail", exit_code=code, error_message=stderr)
                                break
                        else:
                            try:
                                actual = hashlib.sha256((pair_dir / "decrypted.bin").read_bytes()).hexdigest()
                                if actual != expected:
                                    row.update(stage_reached="decrypt", result="fail", exit_code=0, error_message="sha256 mismatch")
                            except OSError as exc:
                                row.update(stage_reached="decrypt", result="fail", exit_code=1, error_message=str(exc))
                    rows.append(row)
                    print(f"repeat={repeat} {key_type} {encryptor}->{decryptor}: {row['result']} ({row['stage_reached']})", flush=True)
    # Replace the file atomically only after the complete run; no partial CSV is mistaken for a full result.
    tmp = args.output.with_suffix(args.output.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, args.output)
    print(f"wrote {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    main()
