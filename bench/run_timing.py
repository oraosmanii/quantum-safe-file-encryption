"""Time encryption and decryption with hyperfine (RQ2).

Runs inside the pqc-bench image, after bench/gen_keys.py:
    docker run --rm -v "$PWD:/work" -w /work pqc-bench python3 bench/run_timing.py --phase pilot

For each measured condition of the phase, in an order shuffled with the seed saved in
results/bench/seed_timing.txt: prepare() it, run hyperfine (2 warm-ups, then the
phase's runs), check the last output's SHA-256, append one row per measured run to
results/bench/timing.csv (INTERFACES.md section 7.4), and keep the hyperfine JSON.

Resumable: a condition that already has rows for this phase is skipped. --force runs
the selected conditions again and replaces their rows. A failed tool call or hash check
is recorded in the rows, then the run stops so it can be investigated.
"""

import argparse
import json
import os
import random
import shlex
import subprocess

import common
from conditions import (PHASE_SIZES, WARMUPS, build_command, cleanup, conditions, gnupghome,
                        input_path, prepare, run_count, sender_home, verify)

SCRIPT = "run_timing"
TIMING = f"{common.RESULTS}/timing.csv"
TIMING_HEADER = ["timestamp_utc", "phase", "condition_id", "mode", "size_id", "file_bytes",
                 "n_recipients", "op", "recipient_position", "run", "wall_s", "exit_code",
                 "sha256_ok", "tool_version", "hyperfine_json"]
SEED_FILE = f"{common.RESULTS}/seed_timing.txt"


def json_path(phase, cond):
    # Pilot JSONs get their own directory, so the full run does not overwrite the files
    # that the pilot rows point to (condition IDs are the same in both phases).
    raw = f"{common.RESULTS}/raw" + ("/pilot" if phase == "pilot" else "")
    return f"{raw}/{cond.condition_id}.json"


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


def gpg_homes(conds):
    """Every GNUPGHOME the measured commands use."""
    homes = set()
    for c in conds:
        if c.tool == "gpg":
            homes.add(sender_home(c.mode) if c.op == "encrypt" else gnupghome(c.mode, c.recipient_id))
    return sorted(homes)


def start_agents(homes):
    """Start gpg-agent for every home before timing, so its startup is never measured."""
    for home in homes:
        common.run(["gpgconf", "--launch", "gpg-agent"], {"GNUPGHOME": home})


def stop_agents(homes):
    for home in homes:
        common.run(["gpgconf", "--kill", "all"], {"GNUPGHOME": home}, check=False)


def hyperfine(cond, cmd, runs, json_out):
    """Run hyperfine on the command; return the result entry of its JSON."""
    common.path(json_out).parent.mkdir(parents=True, exist_ok=True)
    common.path(json_out).unlink(missing_ok=True)
    argv = ["hyperfine", "--shell=none", "--warmup", str(WARMUPS), "--runs", str(runs),
            # A failing call is recorded in exit_codes instead of aborting the benchmark.
            "--ignore-failure",
            "--prepare", shlex.join(["rm", "-f", cmd.output_path]),
            "--export-json", json_out, "--style", "basic",
            shlex.join(cmd.argv)]
    timeout = (WARMUPS + runs) * cond.timeout_s + 60
    try:
        proc = subprocess.run(argv, cwd=common.ROOT, env={**os.environ, **cmd.env}, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"hyperfine timed out after {timeout:g} s") from e
    if proc.returncode != 0:
        raise RuntimeError(f"hyperfine exited with {proc.returncode}")
    return json.loads(common.path(json_out).read_text(encoding="utf-8"))["results"][0]


def time_condition(phase, cond):
    """Time one measured condition and append its rows; return True if it is valid."""
    cmd = build_command(cond)
    runs = run_count(cond, phase)
    json_out = json_path(phase, cond)
    started = common.utc_now()
    prepare(cond)
    result = hyperfine(cond, cmd, runs, json_out)
    ok = verify(cond)
    cleanup(cond)
    times, exit_codes = result["times"], result["exit_codes"]
    if len(times) != runs or len(exit_codes) != runs:
        raise RuntimeError(f"{json_out}: {len(times)} times, {len(exit_codes)} exit codes, want {runs}")
    rows = [{"timestamp_utc": started, "phase": phase, "condition_id": cond.condition_id,
             "mode": cond.mode, "size_id": cond.size_id, "file_bytes": cond.file_bytes,
             "n_recipients": cond.n_recipients, "op": cond.op,
             "recipient_position": cond.recipient_position, "run": i, "wall_s": t,
             "exit_code": code, "sha256_ok": "true" if ok else "false",
             "tool_version": common.tool_version(cond.tool), "hyperfine_json": json_out}
            for i, (t, code) in enumerate(zip(times, exit_codes), start=1)]
    common.append_rows(TIMING, TIMING_HEADER, rows)
    return ok and all(code == 0 for code in exit_codes)


def drop_rows(phase, condition_ids):
    """Remove earlier rows of these conditions in this phase (for --force)."""
    rows = common.read_rows(TIMING, TIMING_HEADER)
    keep = [r for r in rows if not (r["phase"] == phase and r["condition_id"] in condition_ids)]
    if len(keep) != len(rows):
        common.write_rows(TIMING, TIMING_HEADER, keep)
        common.log(SCRIPT, f"--force: replaced {len(rows) - len(keep)} earlier rows of {phase}")


def run(phase, force=False, seed=None, only=None):
    """Time the phase's conditions; return False if one failed (the run stops there)."""
    if phase == "full":
        common.check_full_run_ready(SCRIPT)
    common.check_inputs([input_path(s) for s in PHASE_SIZES[phase]])
    common.ensure_gpg_socket_dir()
    selected = conditions(phase)
    if only:
        known = {c.condition_id for c in selected}
        unknown = sorted(set(only) - known)
        if unknown:
            raise SystemExit(f"error: not conditions of phase {phase}: {', '.join(unknown)}")
        selected = [c for c in selected if c.condition_id in only]
    seed = load_seed(seed)
    random.Random(seed).shuffle(selected)

    if force:
        drop_rows(phase, {c.condition_id for c in selected})
    done = {r["condition_id"] for r in common.read_rows(TIMING, TIMING_HEADER) if r["phase"] == phase}
    todo = [c for c in selected if c.condition_id not in done]
    common.log(SCRIPT, f"phase {phase}, seed {seed}: {len(todo)} to run, "
                       f"{len(selected) - len(todo)} already done")

    homes = gpg_homes(todo)
    start_agents(homes)
    try:
        for i, cond in enumerate(todo, start=1):
            print(f"[{i}/{len(todo)}] {cond.condition_id}", flush=True)
            try:
                valid = time_condition(phase, cond)
            except RuntimeError as e:
                common.log(SCRIPT, f"{cond.condition_id}: {e}", "ERROR")
                return False
            if not valid:
                common.log(SCRIPT, f"{cond.condition_id}: failed tool call or sha256 mismatch; "
                                   f"rows recorded, run stopped. Investigate, then rerun with "
                                   f"--only {cond.condition_id} --force", "ERROR")
                return False
    finally:
        stop_agents(homes)
    common.log(SCRIPT, f"phase {phase}: done")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phase", choices=sorted(PHASE_SIZES), required=True)
    parser.add_argument("--force", action="store_true", help="run again and replace earlier rows")
    parser.add_argument("--seed", type=int, help="shuffle seed for the first run (default: random)")
    parser.add_argument("--only", nargs="+", metavar="CONDITION_ID", help="run only these conditions")
    args = parser.parse_args()
    if not run(args.phase, args.force, args.seed, args.only):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
