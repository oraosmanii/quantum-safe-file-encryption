"""Measure CPU time and peak memory of encryption and decryption (RQ3).

Runs on the host, after bench/run_all.py has generated the keys, because it starts one
fresh pqc-bench container per measured run (measure/runner.py):
    python3 bench/run_resources.py --phase pilot

For each measured condition of the phase, in an order shuffled with the seed saved in
results/bench/seed_resources.txt: prepare() it in a container, measure each of the
phase's runs in its own fresh container (no warm-ups), check the last output's SHA-256,
and append one row per run to results/bench/resources.csv.
The commands come from bench/conditions.py, so they are exactly the timing runs'.

The baseline (run_measured.sh true: container and shell overhead) is shuffled in as one
more entry with the same number of runs and goes to results/bench/resources_baseline.csv.
Values are stored raw; nothing is subtracted here.

Resumable: a condition (or the baseline) that already has rows for this phase is
skipped. --force runs the selected entries again and replaces their rows. A failed tool
call or hash check is recorded in the rows, then the run stops so it can be investigated.
"""

import argparse
import os
import random
import sys

import common
from conditions import PHASE_SIZES, build_command, conditions, input_path, run_count

sys.path.insert(0, str(common.ROOT / "measure"))
import runner  # noqa: E402  (measure/runner.py, host side)

SCRIPT = "run_resources"
RESOURCES = f"{common.RESULTS}/resources.csv"
RESOURCES_HEADER = ["timestamp_utc", "phase", "condition_id", "mode", "size_id", "file_bytes",
                    "n_recipients", "op", "recipient_position", "run", "exit_code",
                    "cpu_user_usec", "cpu_system_usec", "mem_peak_bytes", "max_rss_bytes",
                    "sha256_ok", "tool_version"]
BASELINE = f"{common.RESULTS}/resources_baseline.csv"
BASELINE_HEADER = ["timestamp_utc", "phase", "run", "exit_code", "cpu_user_usec",
                   "cpu_system_usec", "mem_peak_bytes", "max_rss_bytes"]
SEED_FILE = f"{common.RESULTS}/seed_resources.txt"
BASELINE_ID = "baseline"
MEASURES = ("exit_code", "cpu_user_usec", "cpu_system_usec", "mem_peak_bytes", "max_rss_bytes")


def in_image(argv, timeout=common.TIMEOUT, check=True):
    """Run an unmeasured helper command in a fresh container (prepare, verify, cleanup)."""
    return common.run([*runner.docker_argv(), *argv], timeout=timeout + runner.STARTUP_S,
                      check=check)


_versions = {}


def tool_version(tool):
    """`age 1.3.1` or `gnupg 2.5.22` read from the image once.

    The tools exist only in the image, so common.tool_version() cannot be used on the host.
    """
    if tool not in _versions:
        if tool == "age":
            out = in_image(["age", "--version"]).stdout.decode().strip()
            _versions[tool] = "age " + out.removeprefix("v")
        elif tool == "gpg":
            first = in_image(["gpg", "--version"]).stdout.decode().splitlines()[0]
            _versions[tool] = "gnupg " + first.split()[-1]  # "gpg (GnuPG) 2.5.22"
        else:
            raise ValueError(f"unknown tool: {tool}")
    return _versions[tool]


def ensure_writable(paths):
    """Give root-owned result files back to the host user, so this host script can append.

    The scripts in the image run as root, so a file they create first (results/bench/run.log
    from bench/run_all.py) belongs to root on a Linux host, and appending to it fails here.
    The container can still write the file afterwards, because it runs as root.
    """
    if not hasattr(os, "getuid"):
        return
    stuck = [rel for rel in paths
             if common.path(rel).exists() and not os.access(common.path(rel), os.W_OK)]
    if stuck:
        in_image(["chown", f"{os.getuid()}:{os.getgid()}", *stuck])


def load_seed(requested):
    """The saved shuffle seed; a new random one is saved on the first run."""
    p = common.path(SEED_FILE)
    if p.exists():
        seed = int(p.read_text().strip())
        if requested is not None and requested != seed:
            raise SystemExit(f"error: {SEED_FILE} holds seed {seed}, not {requested}")
        return seed
    seed = requested if requested is not None else random.SystemRandom().randrange(2**32)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"{seed}\n", encoding="utf-8")
    return seed


def measure_baseline(phase, runs):
    """Measure `true` runs times and append them to the baseline CSV."""
    rows = []
    for i in range(1, runs + 1):
        started = common.utc_now()
        result = runner.run_measured(["true"])
        rows.append({"timestamp_utc": started, "phase": phase, "run": i,
                     **{k: result[k] for k in MEASURES}})
    common.append_rows(BASELINE, BASELINE_HEADER, rows)
    return all(r["exit_code"] == 0 for r in rows)


def measure_condition(phase, cond):
    """Measure one condition in fresh containers and append its rows; return True if valid."""
    cmd = build_command(cond)
    cid = cond.condition_id
    in_image(["python3", "bench/conditions.py", "prepare", cid], cond.timeout_s)
    rows = []
    for i in range(1, run_count(cond, phase) + 1):
        if i > 1:
            # The output belongs to root in the container, so it is removed there too.
            in_image(["rm", "-f", cmd.output_path])
        started = common.utc_now()
        result = runner.run_measured(cmd.argv, cmd.env, cond.timeout_s)
        if result["exit_code"] != 0:
            common.log(SCRIPT, f"{cid} run {i}: exit code {result['exit_code']}: "
                               f"{result['stderr'].strip()}", "ERROR")
        rows.append({"timestamp_utc": started, "phase": phase, "condition_id": cid,
                     "mode": cond.mode, "size_id": cond.size_id, "file_bytes": cond.file_bytes,
                     "n_recipients": cond.n_recipients, "op": cond.op,
                     "recipient_position": cond.recipient_position, "run": i,
                     **{k: result[k] for k in MEASURES}})
    ok = in_image(["python3", "bench/conditions.py", "verify", cid], cond.timeout_s,
                  check=False).returncode == 0
    in_image(["python3", "bench/conditions.py", "cleanup", cid], cond.timeout_s)
    for row in rows:
        row["sha256_ok"] = "true" if ok else "false"
        row["tool_version"] = tool_version(cond.tool)
    common.append_rows(RESOURCES, RESOURCES_HEADER, rows)
    return ok and all(r["exit_code"] == 0 for r in rows)


def drop_rows(rel, header, phase, keep_row):
    """Remove the rows of this phase that keep_row rejects (for --force)."""
    rows = common.read_rows(rel, header)
    keep = [r for r in rows if r["phase"] != phase or keep_row(r)]
    if len(keep) != len(rows):
        common.write_rows(rel, header, keep)
        common.log(SCRIPT, f"--force: replaced {len(rows) - len(keep)} earlier rows of {phase} in {rel}")


def run(phase, force=False, seed=None, only=None):
    """Measure the phase's conditions; return False if one failed (the run stops there)."""
    ensure_writable([common.RUN_LOG, RESOURCES, BASELINE, SEED_FILE])
    if phase == "full":
        common.check_full_run_ready(SCRIPT)
    common.check_inputs([input_path(s) for s in PHASE_SIZES[phase]])
    selected = conditions(phase)
    try:
        for cond in selected:
            build_command(cond)  # needs keys/MANIFEST.csv
    except RuntimeError as e:
        raise SystemExit(f"error: {e}. Run bench/run_all.py --phase {phase} in the image first.")
    entries = [c.condition_id for c in selected] + [BASELINE_ID]
    if only:
        unknown = sorted(set(only) - set(entries))
        if unknown:
            raise SystemExit(f"error: not conditions of phase {phase}: {', '.join(unknown)}")
        entries = [e for e in entries if e in only]
    seed = load_seed(seed)
    random.Random(seed).shuffle(entries)

    if force:
        drop_rows(RESOURCES, RESOURCES_HEADER, phase, lambda r: r["condition_id"] not in entries)
        if BASELINE_ID in entries:
            drop_rows(BASELINE, BASELINE_HEADER, phase, lambda r: False)
    done = {r["condition_id"] for r in common.read_rows(RESOURCES, RESOURCES_HEADER)
            if r["phase"] == phase}
    if any(r["phase"] == phase for r in common.read_rows(BASELINE, BASELINE_HEADER)):
        done.add(BASELINE_ID)
    todo = [e for e in entries if e not in done]
    common.log(SCRIPT, f"phase {phase}, seed {seed}: {len(todo)} to run, "
                       f"{len(entries) - len(todo)} already done")

    by_id = {c.condition_id: c for c in selected}
    for i, entry in enumerate(todo, start=1):
        print(f"[{i}/{len(todo)}] {entry}", flush=True)
        try:
            if entry == BASELINE_ID:
                # As many runs as a small-file condition of the phase.
                valid = measure_baseline(phase, run_count(selected[0], phase))
            else:
                valid = measure_condition(phase, by_id[entry])
        except RuntimeError as e:
            common.log(SCRIPT, f"{entry}: {e}", "ERROR")
            return False
        if not valid:
            common.log(SCRIPT, f"{entry}: failed tool call or sha256 mismatch; rows recorded, "
                               f"run stopped. Investigate, then rerun with --only {entry} --force",
                       "ERROR")
            return False
    common.log(SCRIPT, f"phase {phase}: done")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phase", choices=sorted(PHASE_SIZES), required=True)
    parser.add_argument("--force", action="store_true", help="run again and replace earlier rows")
    parser.add_argument("--seed", type=int, help="shuffle seed for the first run (default: random)")
    parser.add_argument("--only", nargs="+", metavar="CONDITION_ID",
                        help=f"run only these conditions ({BASELINE_ID} for the baseline)")
    args = parser.parse_args()
    if not run(args.phase, args.force, args.seed, args.only):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
