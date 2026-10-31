"""Generate the test keys of all four modes in keys/ and write keys/MANIFEST.csv.

Runs inside the pqc-bench image:
    docker run --rm -v "$PWD:/work" -w /work pqc-bench python3 bench/gen_keys.py [--force]

Layout, 50 recipients r01 ... r50 per mode:
- age: rNN/id.txt (secret), rNN/recipient.txt (public, one line), and
  recipients_n1/n10/n50.txt with r01 ... rN in that order.
- gpg: rNN/gnupghome (only this recipient's key), rNN/cert.pgp (binary public cert),
  and sender/gnupghome with the 50 public certs and no secret keys.

Idempotent: a recipient whose public key file exists is kept, and keys/MANIFEST.csv is
rebuilt from the keys on disk. --force deletes keys/<mode> and starts over, which
invalidates every result measured with the old keys.
"""

import argparse
import re
import shutil
from datetime import datetime, timezone

import common
from conditions import (MANIFEST, MANIFEST_HEADER, MODES, N_KEYS, RECIPIENT_COUNTS,
                        gnupghome, key_dir, recipients_file, rid, sender_home)

SCRIPT = "gen_keys"
GPG_KEYGEN = ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]

# gpg-cv25519 uses GnuPG's future-default (Ed25519 + cv25519). gpg-pqc uses an Ed25519
# primary key plus a ky768_cv25519 subkey, not the "pqc" shortcut, which in 2.5.22
# pairs ML-KEM-768 with brainpool. Value: (primary algo,
# subkey algo or None, expected subkey curve).
GPG_KEYS = {
    "gpg-cv25519": ("future-default", None, "cv25519"),
    "gpg-pqc": ("ed25519", "ky768_cv25519", "ky768_cv25519"),
}


def colons(home, *args):
    """gpg --with-colons listing lines, split into fields."""
    out = common.run(["gpg", "--batch", "--with-colons", *args], {"GNUPGHOME": home}).stdout
    return [line.split(":") for line in out.decode().splitlines()]


def primary_key(home):
    """(fingerprint, creation time as epoch) of the only primary key in a keyring."""
    lines = colons(home, "--list-keys")
    pubs = [i for i, f in enumerate(lines) if f[0] == "pub"]
    if len(pubs) != 1:
        raise RuntimeError(f"{home}: expected one primary key, found {len(pubs)}")
    fpr = next(f[9] for f in lines[pubs[0]:] if f[0] == "fpr")
    return fpr, int(lines[pubs[0]][5])


def check_composition(mode, home):
    """Ed25519 primary key and exactly one encryption subkey of the mode's algorithm."""
    lines = colons(home, "--list-keys")
    pub = [f for f in lines if f[0] == "pub"]
    subs = [f for f in lines if f[0] == "sub"]
    want = GPG_KEYS[mode][2]
    if (len(pub) != 1 or pub[0][16] != "ed25519" or len(subs) != 1
            or subs[0][11] != "e" or subs[0][16] != want):
        found = [(f[0], f[3], f[11], f[16]) for f in pub + subs]
        raise RuntimeError(f"{home}: unexpected key composition {found}, want ed25519 + {want}")


def stop_daemons(home):
    common.run(["gpgconf", "--kill", "all"], {"GNUPGHOME": home}, check=False)


def gen_gpg(mode, recipient_id):
    """Generate one gpg recipient; return False if it already exists."""
    cert = common.path(f"{key_dir(mode, recipient_id)}/cert.pgp")
    if cert.exists():
        return False
    home = gnupghome(mode, recipient_id)
    shutil.rmtree(common.path(home), ignore_errors=True)  # an interrupted earlier run
    common.path(home).mkdir(mode=0o700, parents=True)
    env = {"GNUPGHOME": home}
    primary, subkey, _ = GPG_KEYS[mode]
    # The same user ID in every mode, so the two gpg modes' certs differ only in key material.
    uid = f"{recipient_id} <{recipient_id}@pqc-bench.test>"
    common.run([*GPG_KEYGEN, "--quick-gen-key", uid, primary, "default", "never"], env)
    fpr, _ = primary_key(home)
    if subkey:
        common.run([*GPG_KEYGEN, "--quick-add-key", fpr, subkey, "encr", "never"], env)
    check_composition(mode, home)
    # Export to a temporary name: cert.pgp only exists once the recipient is complete.
    tmp = cert.with_name("cert.pgp.tmp")
    common.run(["gpg", "--batch", "--yes", "--output", str(tmp), "--export", fpr], env)
    tmp.replace(cert)
    stop_daemons(home)
    return True


def build_sender(mode, rebuild):
    """The sender keyring: all 50 public certs, no secret keys."""
    home = sender_home(mode)
    if common.path(home).exists() and not rebuild:
        return
    shutil.rmtree(common.path(home), ignore_errors=True)
    common.path(home).mkdir(mode=0o700, parents=True)
    env = {"GNUPGHOME": home}
    certs = [f"{key_dir(mode, rid(i))}/cert.pgp" for i in range(1, N_KEYS + 1)]
    common.run(["gpg", "--batch", "--import", *certs], env)
    n_pub = sum(f[0] == "pub" for f in colons(home, "--list-keys"))
    n_sec = sum(f[0] == "sec" for f in colons(home, "--list-secret-keys"))
    stop_daemons(home)
    if n_pub != N_KEYS or n_sec != 0:
        raise RuntimeError(f"{home}: {n_pub} public and {n_sec} secret keys, want {N_KEYS} and 0")


def gen_age(mode, recipient_id):
    """Generate one age recipient; return False if it already exists."""
    kdir = common.path(key_dir(mode, recipient_id))
    recipient = kdir / "recipient.txt"
    if recipient.exists():
        return False
    kdir.mkdir(parents=True, exist_ok=True)
    identity = f"{key_dir(mode, recipient_id)}/id.txt"
    (kdir / "id.txt").unlink(missing_ok=True)  # age-keygen does not overwrite
    pq = ["-pq"] if mode == "age-pq" else []
    common.run(["age-keygen", *pq, "-o", identity])
    public = common.run(["age-keygen", "-y", identity]).stdout.decode().strip()
    tmp = recipient.with_name("recipient.txt.tmp")
    tmp.write_text(public + "\n", encoding="utf-8")
    tmp.replace(recipient)
    return True


def write_recipient_lists(mode):
    publics = [common.path(f"{key_dir(mode, rid(i))}/recipient.txt").read_text().strip()
               for i in range(1, N_KEYS + 1)]
    for n in RECIPIENT_COUNTS:
        common.path(recipients_file(mode, n)).write_text("\n".join(publics[:n]) + "\n",
                                                        encoding="utf-8")


def age_created(mode, recipient_id):
    """The `# created:` time age-keygen writes into the identity file, in UTC."""
    text = common.path(f"{key_dir(mode, recipient_id)}/id.txt").read_text()
    stamp = re.search(r"^# created: (\S+)$", text, re.MULTILINE).group(1)
    return datetime.fromisoformat(stamp).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def manifest_rows():
    rows = []
    for mode in MODES:
        for i in range(1, N_KEYS + 1):
            r = rid(i)
            if mode.startswith("age-"):
                fpr, created = "", age_created(mode, r)
            else:
                fpr, epoch = primary_key(gnupghome(mode, r))
                created = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            rows.append({"mode": mode, "recipient_id": r, "fingerprint": fpr,
                         "created_utc": created})
    return rows


def run(force=False):
    common.ensure_gpg_socket_dir()
    for mode in MODES:
        if force:
            shutil.rmtree(common.path(f"keys/{mode}"), ignore_errors=True)
            common.log(SCRIPT, f"deleted keys/{mode} (--force)")
        made = 0
        for i in range(1, N_KEYS + 1):
            gen = gen_age if mode.startswith("age-") else gen_gpg
            made += gen(mode, rid(i))
        if mode.startswith("age-"):
            write_recipient_lists(mode)
        else:
            build_sender(mode, rebuild=made > 0)
        common.log(SCRIPT, f"{mode}: {made} new, {N_KEYS - made} kept")
    common.write_rows(MANIFEST, MANIFEST_HEADER, manifest_rows())
    common.log(SCRIPT, f"wrote {MANIFEST}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true",
                        help="delete and regenerate all keys (invalidates earlier results)")
    args = parser.parse_args()
    run(args.force)


if __name__ == "__main__":
    main()
