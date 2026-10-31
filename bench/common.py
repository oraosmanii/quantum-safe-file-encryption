"""Shared helpers for the bench/ scripts: paths, tool calls, CSV files, the run log.

Standard library only, so host-side scripts (bench/run_resources.py) can import it too.
Every path is relative to the repo root, and every tool call
runs with the repo root as its working directory, whatever the caller's directory is.
"""

import csv
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = "results/bench"
RUN_LOG = f"{RESULTS}/run.log"
INPUT_HASHES = "results/inputs.sha256"
ENV_JSON = "results/env.json"
TIMEOUT = 60.0


def path(rel):
    """The absolute path of a repo-relative path."""
    return ROOT / rel


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(argv, env=None, timeout=TIMEOUT, check=True):
    """Run argv without a shell in the repo root; return the CompletedProcess (bytes).

    env adds to the current environment. With check, a non-zero exit code raises
    RuntimeError with the full stderr. A timeout always raises RuntimeError.
    """
    full_env = {**os.environ, **(env or {})}
    try:
        proc = subprocess.run(argv, cwd=ROOT, env=full_env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"timeout after {timeout:g} s: {' '.join(argv)}") from e
    if check and proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"exit code {proc.returncode}: {' '.join(argv)}\n{stderr}")
    return proc


def sha256_file(rel):
    h = hashlib.sha256()
    with open(path(rel), "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def input_hashes():
    """{"data/in_1KB.bin": sha256, ...} from results/inputs.sha256."""
    hashes = {}
    for line in path(INPUT_HASHES).read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if digest and name:
            hashes[name.strip()] = digest.strip()
    return hashes


def check_inputs(input_paths):
    """Exit unless every input exists and matches results/inputs.sha256."""
    hashes = input_hashes()
    for rel in input_paths:
        if not path(rel).is_file():
            sys.exit(f"error: {rel} is missing. Run `make inputs` (or, for a pilot on your own "
                     f"machine, `sh measure/make_inputs.sh --force` inside the image).")
        if rel not in hashes:
            sys.exit(f"error: {rel} has no hash in {INPUT_HASHES}")
        if sha256_file(rel) != hashes[rel]:
            sys.exit(f"error: {rel} does not match {INPUT_HASHES}")


def ensure_gpg_socket_dir():
    """Keep gpg-agent's sockets out of the bind-mounted keys/ directory.

    Without /run/user/<uid>, GnuPG puts the agent sockets into GNUPGHOME under keys/.
    When a container exits, its agent is killed without cleanup, and the stale sockets
    stop the next container's agent from starting. With /run/user/<uid>, the sockets
    live inside the container and disappear with it. Only done inside the image.
    """
    if not Path("/.dockerenv").exists():
        return
    Path(f"/run/user/{os.getuid()}").mkdir(mode=0o700, parents=True, exist_ok=True)


_versions = {}


def tool_version(tool):
    """`age 1.3.1` or `gnupg 2.5.22` read from the tool once."""
    if tool not in _versions:
        if tool == "age":
            out = run(["age", "--version"]).stdout.decode().strip()
            _versions[tool] = "age " + out.removeprefix("v")
        elif tool == "gpg":
            first = run(["gpg", "--version"]).stdout.decode().splitlines()[0]
            _versions[tool] = "gnupg " + first.split()[-1]  # "gpg (GnuPG) 2.5.22"
        else:
            raise ValueError(f"unknown tool: {tool}")
    return _versions[tool]


def read_rows(rel, header):
    """The rows of a CSV as dicts; [] if it does not exist. Exits on a wrong header."""
    p = path(rel)
    if not p.exists() or p.stat().st_size == 0:
        return []
    with open(p, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        found = next(reader, [])
        if found != header:
            sys.exit(f"error: {rel} has header {found}, expected {header}")
        return [dict(zip(header, row)) for row in reader]


def append_rows(rel, header, rows):
    """Append rows (dicts) to a CSV, writing the header first if the file is new.

    Refuses to append if the existing header differs from the expected one.
    """
    read_rows(rel, header)  # header check only
    p = path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    new = not p.exists() or p.stat().st_size == 0
    with open(p, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header, lineterminator="\n")
        if new:
            writer.writeheader()
        writer.writerows(rows)


def write_rows(rel, header, rows):
    """Replace a CSV with exactly these rows."""
    p = path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(p)


def log(script, message, level="INFO"):
    """Print a line and append it to results/bench/run.log."""
    line = f"{utc_now()} {level} {script}: {message}"
    print(line, flush=True)
    p = path(RUN_LOG)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def git_head():
    """The current commit, read from .git directly (the image has no git); None if unknown."""
    git = path(".git")
    try:
        if git.is_file():  # worktree: "gitdir: <path>"
            git = Path(git.read_text().split(":", 1)[1].strip())
        head = (git / "HEAD").read_text().strip()
        if not head.startswith("ref: "):
            return head
        ref = head[5:]
        if (git / ref).is_file():
            return (git / ref).read_text().strip()
        for line in (git / "packed-refs").read_text().splitlines():
            if line.endswith(" " + ref):
                return line.split()[0]
    except (OSError, IndexError):
        pass
    return None


def check_full_run_ready(script):
    """Refuse a full run without results/env.json, or with one from another commit."""
    if not path(ENV_JSON).is_file():
        sys.exit(f"error: {ENV_JSON} is missing. Run `make env` on the host right before a full run.")
    env = json.loads(path(ENV_JSON).read_text(encoding="utf-8"))
    head = git_head()
    if head and env.get("git_commit") and env["git_commit"] != head:
        sys.exit(f"error: {ENV_JSON} was captured at commit {env['git_commit'][:12]}, but HEAD is "
                 f"{head[:12]}. Run `make env` again right before the full run.")
    if head is None:
        log(script, "cannot read the git HEAD; env.json commit not checked", "WARN")
    if env.get("git_dirty"):
        log(script, f"{ENV_JSON} records a dirty working tree", "WARN")
