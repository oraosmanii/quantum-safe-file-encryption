"""The measured conditions and the exact tool calls behind them.

The timing runs (run_timing.py) and the resource runs (run_resources.py) both
build their commands here, so they execute exactly the same tool calls. Standard
library only: this module is imported inside the pqc-bench image and on the host.
build_command() only reads files; prepare() and verify() call age and gpg, so they
run inside the image. From the host, call them through the command line:

    python3 bench/conditions.py list --phase pilot     # condition IDs, fixed order
    python3 bench/conditions.py show <condition_id>    # the Command as JSON
    docker run --rm -v "$PWD:/work" -w /work pqc-bench \\
        python3 bench/conditions.py prepare|verify|cleanup <condition_id>

verify exits 0 if the output matches the input's SHA-256 and 1 if it does not.
"""

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass

import common

MODES = ("age-x25519", "age-pq", "gpg-cv25519", "gpg-pqc")
SIZES = {"1KB": 1024, "100KB": 102400, "10MB": 10485760, "1GB": 1073741824}
RECIPIENT_COUNTS = (1, 10, 50)
OPS = ("encrypt", "decrypt")
POSITIONS = ("na", "only", "first", "last")
PHASE_SIZES = {"pilot": ("1KB", "100KB"), "full": tuple(SIZES)}
PILOT_RUNS = 2
WARMUPS = 2
N_KEYS = 50
MANIFEST = "keys/MANIFEST.csv"
MANIFEST_HEADER = ["mode", "recipient_id", "fingerprint", "created_utc"]

# Every gpg call in a measured command. No signing and no compression are constants of
# the experiment; binary output is gpg's default.
GPG = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--trust-model", "always"]


@dataclass(frozen=True)
class Condition:
    mode: str                  # one of MODES
    size_id: str               # a key of SIZES
    n_recipients: int          # 1, 10, 50
    op: str                    # "encrypt" | "decrypt"
    recipient_position: str    # "na" | "only" | "first" | "last"

    def __post_init__(self):
        valid = (self.mode in MODES and self.size_id in SIZES
                 and self.n_recipients in RECIPIENT_COUNTS and self.op in OPS
                 and self.recipient_position in POSITIONS
                 and (self.recipient_position == "na") == (self.op == "encrypt")
                 and (self.recipient_position == "only") == (self.op == "decrypt"
                                                             and self.n_recipients == 1))
        if not valid:
            raise ValueError(f"not a measured condition: {self}")

    @property
    def condition_id(self) -> str:
        return (f"{self.mode}_{self.size_id}_n{self.n_recipients}"
                f"_{self.op}_{self.recipient_position}")

    @property
    def file_bytes(self) -> int:
        return SIZES[self.size_id]

    @property
    def runs(self) -> int:
        """Measured runs in the full phase; see run_count() for the pilot."""
        return 3 if self.size_id == "1GB" else 10

    @property
    def timeout_s(self) -> float:
        """Per tool call."""
        return 900.0 if self.size_id == "1GB" else 60.0

    @property
    def tool(self) -> str:
        return "age" if self.mode.startswith("age-") else "gpg"

    @property
    def recipient_id(self) -> str:
        """The decrypting recipient: r01 for only/first, rN for last; empty for encrypt."""
        if self.op == "encrypt":
            return ""
        return rid(self.n_recipients if self.recipient_position == "last" else 1)


def from_id(condition_id):
    """The Condition of a condition_id, e.g. "age-pq_10MB_n50_decrypt_last"."""
    try:
        mode, size_id, n, op, position = condition_id.split("_")
        cond = Condition(mode, size_id, int(n.removeprefix("n")), op, position)
    except ValueError as e:
        raise ValueError(f"not a condition_id: {condition_id}") from e
    if cond.condition_id != condition_id:
        raise ValueError(f"not a condition_id: {condition_id}")
    return cond


def run_count(cond, phase):
    """Measured runs per condition in a phase."""
    return PILOT_RUNS if phase == "pilot" else cond.runs


def conditions(phase):
    """Every measured condition of the phase, in a fixed order. Callers shuffle."""
    out = []
    for mode in MODES:
        for size_id in PHASE_SIZES[phase]:
            for n in RECIPIENT_COUNTS:
                out.append(Condition(mode, size_id, n, "encrypt", "na"))
                for position in (("only",) if n == 1 else ("first", "last")):
                    out.append(Condition(mode, size_id, n, "decrypt", position))
    return out


# --- key layout ---

def rid(i):
    return f"r{i:02d}"


def key_dir(mode, recipient_id):
    return f"keys/{mode}/{recipient_id}"


def gnupghome(mode, recipient_id):
    return f"{key_dir(mode, recipient_id)}/gnupghome"


def sender_home(mode):
    return f"keys/{mode}/sender/gnupghome"


def recipients_file(mode, n):
    return f"keys/{mode}/recipients_n{n}.txt"


def input_path(size_id):
    return f"data/in_{size_id}.bin"


def ciphertext_path(mode, size_id, n):
    """The ciphertext a decrypt condition reads; made by prepare()."""
    ext = ".age" if mode.startswith("age-") else ".gpg"
    return f"tmp/bench/ct/{mode}_{size_id}_n{n}{ext}"


_fingerprints = {}


def fingerprints(mode):
    """The primary key fingerprints of r01 ... r50 of a gpg mode, from keys/MANIFEST.csv."""
    if mode not in _fingerprints:
        rows = [r for r in common.read_rows(MANIFEST, MANIFEST_HEADER) if r["mode"] == mode]
        fprs = [r["fingerprint"] for r in sorted(rows, key=lambda r: r["recipient_id"])]
        if len(fprs) != N_KEYS or not all(fprs):
            raise RuntimeError(f"{MANIFEST} has no complete key set for {mode}; run bench/gen_keys.py")
        _fingerprints[mode] = fprs
    return _fingerprints[mode]


def encrypt_argv(mode, size_id, n, out_path):
    """argv and extra env of the encryption for recipients r01 ... rN."""
    if mode.startswith("age-"):
        return ["age", "-R", recipients_file(mode, n), "-o", out_path, input_path(size_id)], {}
    argv = [*GPG, "--compress-algo", "none"]
    for fpr in fingerprints(mode)[:n]:
        argv += ["-r", fpr]
    return argv + ["-o", out_path, "-e", input_path(size_id)], {"GNUPGHOME": sender_home(mode)}


def decrypt_argv(mode, recipient_id, in_path, out_path):
    """argv and extra env of a decryption with one recipient's own key."""
    if mode.startswith("age-"):
        identity = f"{key_dir(mode, recipient_id)}/id.txt"
        return ["age", "-d", "-i", identity, "-o", out_path, in_path], {}
    return [*GPG, "-o", out_path, "-d", in_path], {"GNUPGHOME": gnupghome(mode, recipient_id)}


# --- commands ---

@dataclass(frozen=True)
class Command:
    argv: list[str]            # the tool call, paths relative to the repo root
    env: dict[str, str]        # extra environment, e.g. {"GNUPGHOME": "keys/gpg-pqc/r50/gnupghome"}
    input_path: str            # plaintext (encrypt) or ciphertext (decrypt)
    output_path: str           # under tmp/bench/
    expected_sha256: str       # of the plaintext, from results/inputs.sha256


def build_command(cond: Condition) -> Command:
    expected = common.input_hashes()[input_path(cond.size_id)]
    if cond.op == "encrypt":
        ext = ".age" if cond.tool == "age" else ".gpg"
        out = f"tmp/bench/out/{cond.condition_id}{ext}"
        argv, env = encrypt_argv(cond.mode, cond.size_id, cond.n_recipients, out)
        return Command(argv, env, input_path(cond.size_id), out, expected)
    ct = ciphertext_path(cond.mode, cond.size_id, cond.n_recipients)
    out = f"tmp/bench/out/{cond.condition_id}.bin"
    argv, env = decrypt_argv(cond.mode, cond.recipient_id, ct, out)
    return Command(argv, env, ct, out, expected)


def remove(rel):
    try:
        os.remove(common.path(rel))
    except FileNotFoundError:
        pass


def make_ciphertext(mode, size_id, n, timeout):
    """Encrypt the input for r01 ... rN with the measured encrypt command; return the path.

    Always makes a fresh file, so it can never come from older keys or inputs.
    """
    ct = ciphertext_path(mode, size_id, n)
    common.path(ct).parent.mkdir(parents=True, exist_ok=True)
    remove(ct)
    argv, env = encrypt_argv(mode, size_id, n, ct)
    common.run(argv, env, timeout)
    return ct


def prepare(cond: Condition) -> None:
    """Make what the command needs, unmeasured: removes a stale output and, for decrypt,
    writes a fresh ciphertext for (mode, size_id, n_recipients). Raises RuntimeError if
    that encryption fails."""
    cmd = build_command(cond)
    common.path(cmd.output_path).parent.mkdir(parents=True, exist_ok=True)
    remove(cmd.output_path)
    if cond.op == "decrypt":
        make_ciphertext(cond.mode, cond.size_id, cond.n_recipients, cond.timeout_s)


def decrypts_to(mode, recipient_id, ct, expected, timeout):
    """True if recipient_id decrypts ct to the expected SHA-256."""
    out = f"tmp/bench/verify/{os.path.basename(ct)}.{recipient_id}.bin"
    common.path(out).parent.mkdir(parents=True, exist_ok=True)
    remove(out)
    argv, env = decrypt_argv(mode, recipient_id, ct, out)
    try:
        ok = (common.run(argv, env, timeout, check=False).returncode == 0
              and common.sha256_file(out) == expected)
    except (RuntimeError, FileNotFoundError):
        ok = False
    remove(out)
    return ok


def verify(cond: Condition) -> bool:
    """The output of the last run matches the input: for decrypt, its SHA-256; for
    encrypt, the SHA-256 after decrypting it once as r01."""
    cmd = build_command(cond)
    if not common.path(cmd.output_path).is_file():
        return False
    if cond.op == "decrypt":
        return common.sha256_file(cmd.output_path) == cmd.expected_sha256
    return decrypts_to(cond.mode, rid(1), cmd.output_path, cmd.expected_sha256, cond.timeout_s)


def cleanup(cond: Condition) -> None:
    """Remove the condition's output and, for decrypt, its ciphertext (prepare remakes it)."""
    remove(build_command(cond).output_path)
    if cond.op == "decrypt":
        remove(ciphertext_path(cond.mode, cond.size_id, cond.n_recipients))


def main():
    parser = argparse.ArgumentParser(description="Measured conditions and their commands.")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="print every condition_id of a phase").add_argument(
        "--phase", choices=sorted(PHASE_SIZES), required=True)
    for action in ("show", "prepare", "verify", "cleanup"):
        sub.add_parser(action).add_argument("condition_id")
    args = parser.parse_args()

    if args.action == "list":
        for cond in conditions(args.phase):
            print(cond.condition_id)
        return
    try:
        cond = from_id(args.condition_id)
    except ValueError as e:
        sys.exit(f"error: {e}")
    if args.action == "show":
        print(json.dumps({**asdict(build_command(cond)), "timeout_s": cond.timeout_s}, indent=2))
        return
    common.ensure_gpg_socket_dir()
    if args.action == "prepare":
        prepare(cond)
    elif args.action == "verify":
        sys.exit(0 if verify(cond) else 1)
    else:
        cleanup(cond)


if __name__ == "__main__":
    main()
