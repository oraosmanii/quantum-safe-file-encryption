"""Check that measure/run_measured.sh measures what RQ3 needs, and print the evidence.

Runs on the host, after bench/run_all.py has generated the keys:
    python3 measure/validate_measured.py [--runs N]

Writes nothing under results/; it only prints its report. Checks:
1. Baseline: `true` under run_measured.sh, the container and shell overhead.
2. gpg-agent is in the container cgroup whose cpu.stat and memory.peak are read.
3. Agent counted: gpg-pqc decryption with gpg-agent started before the measurement (as
   in the measured runs) and without (gpg starts it inside the measured region). The
   cgroup CPU is compared with the gpg process's own CPU from GNU time (%U + %S), which
   excludes the agent.
4. max_rss_bytes vs. mem_peak_bytes for each mode, encrypt and decrypt.
"""

import argparse
import statistics
import sys

import runner

sys.path.insert(0, str(runner.ROOT / "bench"))
import common  # noqa: E402
from conditions import Condition, build_command  # noqa: E402

DETAIL = "tmp/bench/validate/detail.txt"


def in_image(argv, env=None, check=True):
    return common.run([*runner.docker_argv(env), *argv], timeout=120, check=check)


def measure(argv, env=None, detail=False):
    """run_measured() plus, with detail, the process's own CPU in usec from GNU time."""
    env = dict(env or {})
    if detail:
        env["RUN_MEASURED_DETAIL"] = DETAIL
    result = runner.run_measured(argv, env)
    if result["exit_code"] != 0:
        sys.exit(f"error: exit code {result['exit_code']}: {' '.join(argv)}\n{result['stderr']}")
    if detail:
        _, user_s, sys_s, wall_s = common.path(DETAIL).read_text().split()
        result["proc_cpu_usec"] = round((float(user_s) + float(sys_s)) * 1e6)
        result["wall_s"] = float(wall_s)
    result["cgroup_cpu_usec"] = result["cpu_user_usec"] + result["cpu_system_usec"]
    return result


def summary(results, keys):
    """'key median [min..max]' for each key."""
    parts = []
    for k in keys:
        values = [r[k] for r in results]
        parts.append(f"{k} {statistics.median(values):,.0f} [{min(values):,}..{max(values):,}]")
    return ", ".join(parts)


def check_agent_cgroup():
    home = "keys/gpg-pqc/r01/gnupghome"
    script = ('gpgconf --launch gpg-agent && pid=$(pidof gpg-agent) && '
              'echo "agent pid $pid: $(cat /proc/$pid/cgroup)" && '
              'echo "shell pid $$: $(cat /proc/self/cgroup)"')
    out = in_image(["sh", "-c", script], {"GNUPGHOME": home}).stdout.decode().strip()
    print(out)
    cgroups = {line.rsplit(":", 1)[-1].strip() for line in out.splitlines()}
    print("  same cgroup:", "yes" if len(cgroups) == 1 else "NO")
    return len(cgroups) == 1


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=5, help="runs per measurement (default 5)")
    parser.add_argument("--size", default="100KB", choices=("1KB", "100KB"))
    args = parser.parse_args()
    common.path(DETAIL).parent.mkdir(parents=True, exist_ok=True)
    mem_keys = ("mem_peak_bytes", "max_rss_bytes")
    cpu_keys = ("cgroup_cpu_usec", "proc_cpu_usec")
    ok = True

    print(f"== 1. baseline: run_measured.sh true ({args.runs} runs)")
    base = [measure(["true"]) for _ in range(args.runs)]
    print("  " + summary(base, ("cgroup_cpu_usec", *mem_keys)))

    print("== 2. gpg-agent cgroup")
    ok &= check_agent_cgroup()

    cond = Condition("gpg-pqc", args.size, 1, "decrypt", "only")
    cmd = build_command(cond)
    print(f"== 3. agent counted: {cond.condition_id} ({args.runs} runs each)")
    in_image(["python3", "bench/conditions.py", "prepare", cond.condition_id])
    with_agent = [measure(cmd.argv, cmd.env, detail=True) for _ in range(args.runs)]
    without = [measure(cmd.argv, {**cmd.env, "RUN_MEASURED_NO_AGENT": "1"}, detail=True)
               for _ in range(args.runs)]
    in_image(["python3", "bench/conditions.py", "cleanup", cond.condition_id])
    print("  agent started first:  " + summary(with_agent, (*cpu_keys, *mem_keys)))
    print("  agent started by gpg: " + summary(without, (*cpu_keys, *mem_keys)))
    extra = [r["cgroup_cpu_usec"] - r["proc_cpu_usec"] for r in with_agent]
    print(f"  cgroup CPU - gpg process CPU (agent started first): median {statistics.median(extra):,.0f} usec")
    startup = (statistics.median(r["cgroup_cpu_usec"] for r in without)
               - statistics.median(r["cgroup_cpu_usec"] for r in with_agent))
    print(f"  agent startup inside the measured region adds: median {startup:,.0f} usec")
    if startup <= 0:
        print("  WARNING: no extra CPU when gpg starts the agent; agent CPU may not be counted")
        ok = False

    print(f"== 4. max_rss_bytes vs. mem_peak_bytes ({args.size}, n=1, {args.runs} runs each)")
    for mode in ("age-x25519", "age-pq", "gpg-cv25519", "gpg-pqc"):
        for op, pos in (("encrypt", "na"), ("decrypt", "only")):
            cond = Condition(mode, args.size, 1, op, pos)
            cmd = build_command(cond)
            in_image(["python3", "bench/conditions.py", "prepare", cond.condition_id])
            results = []
            for i in range(args.runs):
                if i:
                    in_image(["rm", "-f", cmd.output_path])
                results.append(measure(cmd.argv, cmd.env))
            verified = in_image(["python3", "bench/conditions.py", "verify", cond.condition_id],
                                check=False).returncode == 0
            in_image(["python3", "bench/conditions.py", "cleanup", cond.condition_id])
            ok &= verified
            print(f"  {cond.condition_id}: " + summary(results, ("cgroup_cpu_usec", *mem_keys))
                  + ("" if verified else "  SHA-256 MISMATCH"))

    print("== result:", "all checks passed" if ok else "CHECKS FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
