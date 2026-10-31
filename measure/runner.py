"""Measure CPU time and peak memory of one tool call in a fresh container (RQ3).

Host side of measure/run_measured.sh. Every call starts one
fresh pqc-bench container, because the cgroup's memory.peak never decreases within a
container. Used by bench/run_resources.py; also runnable by hand:

    python3 measure/runner.py [-e NAME=VALUE ...] [--timeout S] -- <command...>

which prints the result as JSON. Standard library only.
"""

import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "pqc-bench"
SCRIPT = "measure/run_measured.sh"
FIELDS = ("exit_code", "cpu_user_usec", "cpu_system_usec", "mem_peak_bytes", "max_rss_bytes")
# Time to start and remove a container, on top of the tool call's own timeout.
STARTUP_S = 60.0


def docker_argv(env=None, name=None):
    """`docker run` for a fresh pqc-bench container with the repo at /work, up to the image."""
    argv = ["docker", "run", "--rm", "--cgroupns=private", "-v", f"{ROOT}:/work", "-w", "/work"]
    if name:
        argv += ["--name", name]
    for key, value in (env or {}).items():
        argv += ["-e", f"{key}={value}"]
    return argv + [IMAGE]


def parse_line(stdout):
    """The five integers of run_measured.sh's single output line, or None."""
    lines = stdout.splitlines()
    if len(lines) != 1:
        return None
    parts = lines[0].split(",")
    if len(parts) != len(FIELDS):
        return None
    try:
        return dict(zip(FIELDS, (int(p) for p in parts)))
    except ValueError:
        return None


def run_measured(argv: list[str], env: dict[str, str] | None = None,
                 timeout: float = 60.0) -> dict:
    """Run argv in one fresh container under run_measured.sh; return its measurements.

    timeout limits the tool call itself (coreutils timeout inside the container, outside
    the measured region); the container gets STARTUP_S more to start. A failing tool
    comes back with a non-zero exit_code. RuntimeError only if the container fails to
    start, the output cannot be parsed, or the timeout expires.
    """
    name = f"pqc-measure-{uuid.uuid4().hex[:12]}"
    cmd = [*docker_argv(env, name), "timeout", "-s", "KILL", f"{timeout:g}", "sh", SCRIPT, *argv]
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=timeout + STARTUP_S)
    except subprocess.TimeoutExpired as e:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=STARTUP_S)
        raise RuntimeError(f"timeout after {timeout + STARTUP_S:g} s (container): {' '.join(argv)}") from e
    except OSError as e:
        raise RuntimeError(f"cannot run docker: {e}") from e
    stdout = proc.stdout.decode(errors="replace")
    stderr = proc.stderr.decode(errors="replace")
    if proc.returncode == 137:  # coreutils timeout -s KILL: the tool call ran out of time
        raise RuntimeError(f"timeout after {timeout:g} s: {' '.join(argv)}\n{stderr.strip()}")
    result = parse_line(stdout)
    if proc.returncode != 0 or result is None:
        raise RuntimeError(f"measurement failed (docker exit code {proc.returncode}): "
                           f"{' '.join(argv)}\nstdout: {stdout.strip()}\nstderr: {stderr.strip()}")
    result["stderr"] = stderr
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-e", "--env", action="append", default=[], metavar="NAME=VALUE",
                        help="environment variable for the command (repeatable)")
    parser.add_argument("--timeout", type=float, default=60.0, help="tool call timeout in s")
    parser.add_argument("command", nargs="+", help="the command, after --")
    args = parser.parse_args()
    env = {}
    for item in args.env:
        key, sep, value = item.partition("=")
        if not sep:
            sys.exit(f"error: not NAME=VALUE: {item}")
        env[key] = value
    try:
        print(json.dumps(run_measured(args.command, env, args.timeout), indent=2))
    except RuntimeError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
