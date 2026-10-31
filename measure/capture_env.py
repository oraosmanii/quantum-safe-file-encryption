"""Write results/env.json: the machine, Docker, container, and tool versions of a run.

Runs on the host, from any directory, before every full run.
bench/run_all.py and bench/run_resources.py refuse to start a full run without the file.

Every value is read from the system at capture time. A value that cannot be read is
null, never guessed. The script fails without writing anything if Docker or the
pqc-bench image is unavailable, because the tool versions would then be missing.

usage: python3 measure/capture_env.py [--force] [--out PATH]
"""

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "results" / "env.json"
IMAGE = "pqc-bench"
TIMEOUT = 60.0

# tools key -> command run in a fresh pqc-bench container.
# libgcrypt and sequoia_openpgp are extracted from the gpgconf and sq outputs below.
TOOL_COMMANDS = {
    "age": ["age", "--version"],
    "age_keygen": ["age-keygen", "--version"],
    "gpg": ["gpg", "--version"],
    "sq": ["sq", "version"],
    "openssl": ["openssl", "version", "-a"],
    "gopenpgp": ["gopenpgp-cli", "version"],
    "hyperfine": ["hyperfine", "--version"],
    "gnu_time": ["/usr/bin/time", "--version"],
    "python": ["python3", "--version"],
}


def run(argv, timeout=TIMEOUT, require_ok=True):
    """Run argv without a shell; return its output, or None if it cannot be read.

    Some tools print their version to stderr (sq), so stdout is used if it is
    non-empty and stderr otherwise.
    """
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if require_ok and proc.returncode != 0:
        return None
    out = proc.stdout.strip() or proc.stderr.strip()
    return out or None


def in_image(argv, require_ok=True):
    return run(["docker", "run", "--rm", IMAGE, *argv], require_ok=require_ok)


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def os_release_name(text):
    if text is None:
        return None
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key == "PRETTY_NAME":
            return value.strip().strip('"')
    return None


def is_wsl():
    return "microsoft" in platform.release().lower()


def windows_version():
    """The Windows build under WSL2, via WSL interop; None elsewhere."""
    if not is_wsl():
        return None
    out = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
               "$os = Get-CimInstance Win32_OperatingSystem; \"$($os.Caption) $($os.Version)\""],
              timeout=30)
    return out.strip() if out else None


def cpu_model():
    text = read_text("/proc/cpuinfo")
    if text is None:
        return None
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "model name":
            return value.strip()
    return None


def ram_bytes():
    text = read_text("/proc/meminfo")
    if text is None:
        return None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024  # /proc/meminfo reports kB
    return None


def cgroup_version():
    if Path("/sys/fs/cgroup/cgroup.controllers").exists():
        return 2
    if Path("/sys/fs/cgroup").is_dir():
        return 1
    return None


def cpu_governor():
    # Not exposed inside a WSL2 VM, where Windows controls frequency scaling.
    return read_text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")


def on_ac_power():
    if is_wsl():
        # The WSL2 VM has no power_supply devices, so ask Windows through interop.
        out = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                   "Add-Type -AssemblyName System.Windows.Forms; "
                   "[System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus"],
                  timeout=30)
        return {"Online": True, "Offline": False}.get((out or "").strip())
    mains = []
    for supply in Path("/sys/class/power_supply").glob("*"):
        if read_text(supply / "type") == "Mains":
            mains.append(read_text(supply / "online"))
    if not mains or None in mains:
        return None
    return "1" in mains


def host_info():
    name = os_release_name(read_text("/etc/os-release"))
    winver = windows_version()
    if name and winver:
        name = f"{name} (WSL2 on {winver})"
    return {
        "cpu_model": cpu_model(),
        "cores": os.cpu_count(),  # logical CPUs visible to the host OS
        "ram_bytes": ram_bytes(),
        "os": name,
        "kernel": platform.release() or None,
        "cgroup_version": cgroup_version(),
        "cpu_governor": cpu_governor(),
        "on_ac_power": on_ac_power(),
    }


def docker_info():
    version = run(["docker", "version"])
    # The local image ID (sha256 of the image config). A locally built image has no
    # registry digest, so this ID is what identifies the exact image that ran.
    digest = run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE])
    if version is None or digest is None:
        sys.exit(f"error: cannot read Docker or the {IMAGE} image. Start Docker and run `make image`.")
    return {"version": version, "image": IMAGE, "image_digest": digest}


def section(text, header):
    """The block of gpgconf --show-versions output that starts with `* <header>`."""
    if text is None:
        return None
    lines, inside = [], False
    for line in text.splitlines():
        if line.startswith("* "):
            inside = line.startswith(f"* {header} ")
        if inside:
            if not line.strip():
                break
            lines.append(line)
    return "\n".join(lines) or None


def tools_info():
    tools = {key: in_image(argv) for key, argv in TOOL_COMMANDS.items()}

    # gpgconf exits non-zero because the image has no dirmngr, but the library
    # versions it prints before that are the ones gpg actually links against.
    gpgconf = in_image(["gpgconf", "--show-versions"], require_ok=False)
    tools["libgcrypt"] = section(gpgconf, "Libgcrypt")

    sq = tools["sq"] or ""
    tools["sequoia_openpgp"] = next(
        (line.strip() for line in sq.splitlines() if "sequoia-openpgp" in line), None)

    # Debian's GNU time binary reports its version as UNKNOWN, so add the package version.
    pkg = in_image(["dpkg-query", "-W", "-f", "${Package} ${Version}", "time"])
    if tools["gnu_time"] and pkg:
        tools["gnu_time"] = f"{tools['gnu_time']}\n(Debian package: {pkg})"

    order = ["age", "age_keygen", "gpg", "libgcrypt", "sq", "sequoia_openpgp",
             "openssl", "gopenpgp", "hyperfine", "gnu_time", "python"]
    return {key: tools[key] for key in order}


def git_info():
    commit = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    try:
        status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                                capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return commit, None
    if status.returncode != 0:
        return commit, None
    return commit, bool(status.stdout.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="overwrite an existing env.json")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output path")
    args = parser.parse_args()

    if args.out.exists() and not args.force:
        print(f"{args.out} exists; use --force to capture a new one")
        return

    captured = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit, dirty = git_info()
    docker = docker_info()
    container = {
        "os": os_release_name(in_image(["cat", "/etc/os-release"])),
        "kernel": in_image(["uname", "-r"]),
    }
    env = {
        "captured_utc": captured,
        "git_commit": commit,
        "git_dirty": dirty,
        "host": host_info(),
        "docker": docker,
        "container": container,
        "tools": tools_info(),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8", newline="\n")
    tmp.replace(args.out)
    print(f"wrote {args.out}")
    nulls = [f"{group}.{key}" for group in ("host", "container", "tools")
             for key, value in env[group].items() if value is None]
    if nulls:
        print("not readable (null): " + ", ".join(nulls))


if __name__ == "__main__":
    main()
