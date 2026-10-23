"""Measure public key sizes and ciphertext sizes (RQ1).

Runs inside the pqc-bench image, after bench/gen_keys.py:
    docker run --rm -v "$PWD:/work" -w /work pqc-bench python3 bench/sizes.py --phase pilot

Writes (INTERFACES.md sections 2 and 7):
- results/bench/key_sizes.csv: one row per mode and recipient.
- results/bench/sizes.csv: one row per condition (mode, size_id, n_recipients) of the phase.
  The ciphertext comes from the same encrypt command the timing runs measure, and
  sha256_ok says whether it decrypts as r01 to the input.
- results/bench/inspect/<mode>_n<N>.txt: age-inspect or gpg --list-packets of the 1KB
  ciphertext, to show where the bytes go.

Sizes are deterministic, so each is measured once. Rows that exist are kept;
--force measures everything again and replaces both CSVs.
"""

import argparse
import re

import common
from conditions import (MODES, N_KEYS, PHASE_SIZES, RECIPIENT_COUNTS, SIZES, decrypts_to,
                        gnupghome, input_path, key_dir, make_ciphertext, remove, rid)

SCRIPT = "sizes"
KEY_SIZES = f"{common.RESULTS}/key_sizes.csv"
KEY_SIZES_HEADER = ["mode", "recipient_id", "public_key_bytes", "enc_subkey_packet_bytes",
                    "tool_version", "timestamp_utc"]
SIZES_CSV = f"{common.RESULTS}/sizes.csv"
SIZES_HEADER = ["mode", "size_id", "file_bytes", "n_recipients", "ciphertext_bytes",
                "overhead_bytes", "sha256_ok", "tool_version", "timestamp_utc"]
INSPECT_SIZE = "1KB"

# gpg --list-packets prints "# off=<offset> ctb=<ctb> tag=<tag> hlen=<header> plen=<body>"
# before each packet. Tag 14 is a public subkey packet.
PACKET = re.compile(r"^# off=\d+ ctb=[0-9a-f]+ tag=(\d+) hlen=(\d+) plen=(\d+)", re.MULTILINE)
SUBKEY_TAG = 14


def tool(mode):
    return "age" if mode.startswith("age-") else "gpg"


def gpg_key_sizes(mode, recipient_id):
    """(full binary cert bytes, encryption subkey packet bytes incl. its header)."""
    home = gnupghome(mode, recipient_id)
    cert = common.run(["gpg", "--batch", "--export"], {"GNUPGHOME": home}).stdout
    listing = common.run(["gpg", "--batch", "--list-packets",
                          f"{key_dir(mode, recipient_id)}/cert.pgp"],
                         {"GNUPGHOME": home}).stdout.decode()
    subkeys = [int(h) + int(p) for tag, h, p in PACKET.findall(listing) if int(tag) == SUBKEY_TAG]
    if len(subkeys) != 1:
        raise RuntimeError(f"{mode} {recipient_id}: expected one subkey packet, found {len(subkeys)}")
    return len(cert), subkeys[0]


def measure_key_sizes(force):
    rows = [] if force else common.read_rows(KEY_SIZES, KEY_SIZES_HEADER)
    done = {(r["mode"], r["recipient_id"]) for r in rows}
    new = []
    for mode in MODES:
        for i in range(1, N_KEYS + 1):
            r = rid(i)
            if (mode, r) in done:
                continue
            if tool(mode) == "age":
                public = common.path(f"{key_dir(mode, r)}/recipient.txt").read_text().strip()
                public_bytes, subkey_bytes = len(public.encode()), ""
            else:
                public_bytes, subkey_bytes = gpg_key_sizes(mode, r)
            new.append({"mode": mode, "recipient_id": r, "public_key_bytes": public_bytes,
                        "enc_subkey_packet_bytes": subkey_bytes,
                        "tool_version": common.tool_version(tool(mode)),
                        "timestamp_utc": common.utc_now()})
    if force:
        common.write_rows(KEY_SIZES, KEY_SIZES_HEADER, new)
    else:
        common.append_rows(KEY_SIZES, KEY_SIZES_HEADER, new)
    common.log(SCRIPT, f"{KEY_SIZES}: {len(new)} rows measured, {len(done)} kept")


def write_inspect(mode, n, ct):
    """Save the packet/stanza listing of a ciphertext to results/bench/inspect/."""
    if tool(mode) == "age":
        argv, env = ["age-inspect", ct], {}
    else:
        # As r01, so gpg also lists the packets inside the encrypted data.
        argv, env = ["gpg", "--batch", "--list-packets", ct], {"GNUPGHOME": gnupghome(mode, rid(1))}
    proc = common.run(argv, env, check=False)
    out = common.path(f"{common.RESULTS}/inspect/{mode}_n{n}.txt")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        f"# {' '.join(argv)}\n# input: {input_path(INSPECT_SIZE)}, recipients r01 ... r{n:02d}, "
        f"{common.tool_version(tool(mode))}, exit code {proc.returncode}\n"
        f"# --- stdout\n{proc.stdout.decode(errors='replace')}"
        f"# --- stderr\n{proc.stderr.decode(errors='replace')}", encoding="utf-8")


def measure_ciphertexts(phase, force):
    rows = [] if force else common.read_rows(SIZES_CSV, SIZES_HEADER)
    done = {(r["mode"], r["size_id"], int(r["n_recipients"])) for r in rows}
    hashes = common.input_hashes()
    new = []
    for mode in MODES:
        for size_id in PHASE_SIZES[phase]:
            timeout = 900.0 if size_id == "1GB" else common.TIMEOUT
            for n in RECIPIENT_COUNTS:
                if (mode, size_id, n) in done:
                    continue
                ct = make_ciphertext(mode, size_id, n, timeout)
                ct_bytes = common.path(ct).stat().st_size
                ok = decrypts_to(mode, rid(1), ct, hashes[input_path(size_id)], timeout)
                if size_id == INSPECT_SIZE:
                    write_inspect(mode, n, ct)
                remove(ct)
                row = {"mode": mode, "size_id": size_id, "file_bytes": SIZES[size_id],
                       "n_recipients": n, "ciphertext_bytes": ct_bytes,
                       "overhead_bytes": ct_bytes - SIZES[size_id],
                       "sha256_ok": "true" if ok else "false",
                       "tool_version": common.tool_version(tool(mode)),
                       "timestamp_utc": common.utc_now()}
                new.append(row)
                if not ok:
                    common.log(SCRIPT, f"sha256 mismatch: {mode} {size_id} n{n}", "ERROR")
    if force:
        # Keep rows of sizes outside this phase; replace the ones measured again.
        kept = [r for r in common.read_rows(SIZES_CSV, SIZES_HEADER)
                if r["size_id"] not in PHASE_SIZES[phase]]
        common.write_rows(SIZES_CSV, SIZES_HEADER, kept + new)
    else:
        common.append_rows(SIZES_CSV, SIZES_HEADER, new)
    common.log(SCRIPT, f"{SIZES_CSV}: {len(new)} rows measured, {len(done)} kept")
    return all(r["sha256_ok"] == "true" for r in new)


def run(phase, force=False):
    """Measure the phase's sizes; return False if any ciphertext failed its hash check."""
    common.check_inputs([input_path(s) for s in PHASE_SIZES[phase]])
    common.ensure_gpg_socket_dir()
    measure_key_sizes(force)
    return measure_ciphertexts(phase, force)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phase", choices=sorted(PHASE_SIZES), required=True)
    parser.add_argument("--force", action="store_true", help="measure again and replace the rows")
    args = parser.parse_args()
    if not run(args.phase, args.force):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
