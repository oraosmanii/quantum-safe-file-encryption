"""Uniform, isolated adapters for the pinned OpenPGP implementations."""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

TOOLS = ("gpg", "sq", "gopenpgp")
TIMEOUT = 60


def _run(argv, workdir, *, env=None):
    started = time.monotonic()
    try:
        p = subprocess.run([str(x) for x in argv], cwd=workdir, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=TIMEOUT)
        return p.returncode == 0, p.returncode, p.stderr, time.monotonic() - started, p.stdout
    except subprocess.TimeoutExpired as exc:
        err = exc.stderr or ""
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return False, 124, f"timeout after {TIMEOUT}s\n{err}", time.monotonic() - started, ""
    except OSError as exc:
        return False, 127, str(exc), time.monotonic() - started, ""


def _home(tool, workdir):
    home = Path(workdir) / "homes" / tool
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    return home


def _env(tool, workdir):
    env = os.environ.copy()
    if tool == "gpg":
        env["GNUPGHOME"] = str(_home(tool, workdir))
    elif tool == "sq":
        env["SEQUOIA_HOME"] = str(_home(tool, workdir))
    return env


def keygen(tool, key_type, workdir):
    """Return (secret_path, public_cert_path), raising RuntimeError on failure."""
    if tool not in TOOLS or key_type not in ("classical", "pqc"):
        raise ValueError(f"unsupported tool/key type: {tool}/{key_type}")
    wd = Path(workdir).resolve()
    wd.mkdir(parents=True, exist_ok=True)
    sec, pub = wd / f"{tool}-{key_type}.sec.pgp", wd / f"{tool}-{key_type}.pub.pgp"
    env = _env(tool, wd)
    uid = f"Interop Test <interop-{tool}-{key_type}@example.invalid>"
    if tool == "gopenpgp":
        args = ["gopenpgp-cli", "keygen", "--" + key_type, "--uid", uid,
                "--out-secret", sec, "--out-public", pub]
        result = _run(args, wd, env=env)
        _require(result, "keygen")
    elif tool == "sq":
        profile = "rfc4880" if key_type == "classical" else "rfc9580"
        suite = "cv25519" if key_type == "classical" else "mldsa65-ed25519"
        result = _run(["sq", "--home", str(_home(tool, wd)), "key", "generate",
                       "--own-key", "--name", "Interop Test", "--email",
                       f"interop-{tool}-{key_type}@example.invalid", "--without-password",
                       "--profile", profile, "--cipher-suite", suite,
                       "--output", sec, "--rev-cert", wd / "revoke.asc"], wd, env=env)
        _require(result, "keygen")
        result = _run(["sq", "--home", str(_home(tool, wd)), "key", "delete",
                       f"--cert-file={sec}", f"--output={pub}"], wd, env=env)
        _require(result, "public certificate export")
    else:
        # gpg-pqc uses Ed25519 plus ky768_cv25519; the pqc shortcut is deliberately avoided.
        args = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
                "--passphrase", "", "--quick-gen-key", uid,
                "ed25519" if key_type == "pqc" else "future-default", "default", "never"]
        result = _run(args, wd, env=env)
        _require(result, "keygen")
        listed = _run(["gpg", "--batch", "--with-colons", "--list-secret-keys"], wd, env=env)
        _require(listed, "key fingerprint lookup")
        fprs = re.findall(r"(?m)^fpr:::::::::([0-9A-F]+):", listed[4])
        if not fprs:
            raise RuntimeError("gpg keygen: no fingerprint in --list-secret-keys output")
        fpr = fprs[0]
        if key_type == "pqc":
            result = _run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
                           "--passphrase", "", "--quick-add-key", fpr,
                           "ky768_cv25519", "encr", "never"], wd, env=env)
            _require(result, "PQC encryption subkey generation")
        result = _run(["gpg", "--batch", "--yes", "--output", pub, "--export", fpr], wd, env=env)
        _require(result, "public certificate export")
        result = _run(["gpg", "--batch", "--yes", "--output", sec, "--export-secret-keys", fpr], wd, env=env)
        _require(result, "secret key export")
    return str(sec), str(pub)


def _require(result, action):
    ok, code, stderr, _, _ = result
    if not ok:
        raise RuntimeError(f"{action} failed (exit {code}): {stderr}")


def import_cert(tool, cert_path, workdir):
    wd, cert = Path(workdir).resolve(), Path(cert_path).resolve()
    env = _env(tool, wd)
    if tool == "gpg":
        raw = _run(["gpg", "--batch", "--import", cert], wd, env=env)
    elif tool == "sq":
        raw = _run(["sq", "--home", str(_home(tool, wd)), "cert", "import", cert], wd, env=env)
    else:
        # GopenPGP has no persistent keyring/import operation. Its adapter's import
        # stage is loading and parsing the public cert before encryption.
        raw = _run(["gopenpgp-cli", "validate", "--key", cert], wd, env=env)
    return raw[:4]


def encrypt(tool, cert_path, in_path, out_path, workdir):
    wd, cert = Path(workdir).resolve(), Path(cert_path).resolve()
    source, out = Path(in_path).resolve(), Path(out_path).resolve()
    env = _env(tool, wd)
    if tool == "gpg":
        listed = _run(["gpg", "--batch", "--with-colons", "--import-options", "show-only", "--import", cert], wd, env=env)
        if not listed[0]:
            return listed[:4]
        fprs = re.findall(r"(?m)^fpr:::::::::([0-9A-F]+):", listed[4])
        if not fprs:
            return False, 1, "could not determine recipient fingerprint from public cert", listed[3]
        args = ["gpg", "--batch", "--yes", "--trust-model", "always", "--compress-algo", "none",
                "--recipient", fprs[0], "--output", out, "--encrypt", source]
    elif tool == "sq":
        args = ["sq", "--home", str(_home(tool, wd)), "encrypt", "--binary", "--without-signature",
                "--for-file", cert, "--output", out, source]
    else:
        args = ["gopenpgp-cli", "encrypt", "--recipient", cert, "--in", source, "--out", out]
    return _run(args, wd, env=env)[:4]


def decrypt(tool, secret_path, in_path, out_path, workdir):
    wd, secret = Path(workdir).resolve(), Path(secret_path).resolve()
    source, out = Path(in_path).resolve(), Path(out_path).resolve()
    env = _env(tool, wd)
    if tool == "gpg":
        # The private key was generated in a separate, isolated keygen home.
        # Load that exported secret key into this pair's fresh home before decrypting.
        loaded = _run(["gpg", "--batch", "--import", secret], wd, env=env)
        if not loaded[0]:
            return loaded[:4]
        args = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
                "--no-symkey-cache", "--output", out, "--decrypt", source]
    elif tool == "sq":
        args = ["sq", "--home", str(_home(tool, wd)), "decrypt", "--recipient-file", secret, "--output", out, source]
    else:
        args = ["gopenpgp-cli", "decrypt", "--key", secret, "--in", source, "--out", out]
    return _run(args, wd, env=env)[:4]


def version(tool, workdir):
    wd = Path(workdir).resolve()
    wd.mkdir(parents=True, exist_ok=True)
    args = {"gpg": ["gpg", "--version"], "sq": ["sq", "version"],
            "gopenpgp": ["gopenpgp-cli", "version"]}[tool]
    r = _run(args, wd, env=_env(tool, wd))
    if not r[0]:
        return f"unavailable (exit {r[1]}): {r[2].strip()}"
    # sq version writes its version block to stderr; smoke_test.sh captures it
    # with 2>&1. Other tools print their version to stdout.
    output = ((r[4] + "\n" + r[2]) if tool == "sq" else r[4]).strip()
    return (output.splitlines() or ["unknown"])[0].strip()
