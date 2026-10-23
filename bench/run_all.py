"""Run the whole benchmark (RQ1, RQ2): keys, sizes, timing.

Runs inside the pqc-bench image:
    docker run --rm -v "$PWD:/work" -w /work pqc-bench python3 bench/run_all.py --phase pilot

--phase pilot: 1KB and 100KB, 2 runs per measured condition.
--phase full: all four sizes, 10 runs (3 for 1GB). Started by a human on the
measurement machine, right after `make env` on the host.

Steps: bench/gen_keys.py (keeps existing keys), bench/sizes.py, bench/run_timing.py.
Every step is resumable, so running this again continues where it stopped. --force
measures sizes and timing again; it never regenerates keys (use gen_keys.py --force).
Start, end, and errors go to results/bench/run.log.
"""

import argparse

import common
import gen_keys
import run_timing
import sizes
from conditions import PHASE_SIZES, input_path

SCRIPT = "run_all"


def run(phase, force=False, seed=None):
    if phase == "full":
        common.check_full_run_ready(SCRIPT)
    common.check_inputs([input_path(s) for s in PHASE_SIZES[phase]])
    common.log(SCRIPT, f"start phase {phase}" + (" (--force)" if force else ""))
    try:
        gen_keys.run()
        if not sizes.run(phase, force):
            common.log(SCRIPT, "sizes: sha256 mismatch, stopped before timing", "ERROR")
            return False
        if not run_timing.run(phase, force, seed):
            common.log(SCRIPT, "timing stopped on a failed condition (see above)", "ERROR")
            return False
    except (RuntimeError, OSError) as e:
        common.log(SCRIPT, f"{type(e).__name__}: {e}", "ERROR")
        return False
    common.log(SCRIPT, f"end phase {phase}")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phase", choices=sorted(PHASE_SIZES), required=True)
    parser.add_argument("--force", action="store_true",
                        help="measure sizes and timing again (keys are kept)")
    parser.add_argument("--seed", type=int, help="timing shuffle seed for the first run")
    args = parser.parse_args()
    if not run(args.phase, args.force, args.seed):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
