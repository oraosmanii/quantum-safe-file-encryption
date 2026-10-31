#!/bin/sh
# Measure CPU time and peak memory of one command (RQ3).
# Runs inside a fresh pqc-bench container, one container per measured run, because
# the cgroup's memory.peak is a maximum over the whole lifetime of the container.
# Started by measure/runner.py on the host; timing is measured separately (hyperfine).
#
# usage: sh measure/run_measured.sh <command...>
#
# Prints exactly one line on stdout:
#     exit_code,cpu_user_usec,cpu_system_usec,mem_peak_bytes,max_rss_bytes
# - cpu_*_usec: delta of the container cgroup's cpu.stat around the command, so it
#   includes gpg-agent, which runs in the same cgroup.
# - mem_peak_bytes: the container cgroup's memory.peak (everything in the container,
#   including gpg-agent and page cache).
# - max_rss_bytes: GNU time %M of the command's own process, in bytes.
# The command's stdout and stderr both go to stderr. A failing command is a result,
# not an error: its exit code is the first field. If the measurement itself cannot be
# made, the script prints no line and exits 125.
#
# If GNUPGHOME is set, gpg-agent is started before the measurement begins, as in the
# timing runs, so the agent's startup is not measured but its work for the command is.
#
# For validation only (measure/validate_measured.py), never in the measured runs:
# - RUN_MEASURED_DETAIL=<path>: also write GNU time's "%M %U %S %e" line for the command
#   (max RSS in KB, the process's own user and system CPU in s, wall time in s) there.
# - RUN_MEASURED_NO_AGENT=1: do not start gpg-agent first, so gpg starts it inside the
#   measured region.
set -u

CG=/sys/fs/cgroup

fail() {
    echo "run_measured.sh: $*" >&2
    exit 125
}

[ $# -gt 0 ] || fail "usage: sh measure/run_measured.sh <command...>"
[ "$(stat -fc %T "$CG")" = cgroup2fs ] || fail "$CG is not cgroup v2"
[ -r "$CG/cpu.stat" ] || fail "$CG/cpu.stat is not readable"
[ -r "$CG/memory.peak" ] || fail "$CG/memory.peak is not readable (kernel >= 5.19 needed)"

if [ -n "${GNUPGHOME:-}" ]; then
    # Without this directory the agent sockets land in GNUPGHOME under keys/.
    [ -d "/run/user/$(id -u)" ] || fail "/run/user/$(id -u) is missing; rebuild the image (make image)"
    if [ -z "${RUN_MEASURED_NO_AGENT:-}" ]; then
        gpgconf --launch gpg-agent || fail "cannot start gpg-agent for GNUPGHOME=$GNUPGHOME"
    fi
fi

cpu_usec() {
    awk -v key="$1" '$1 == key { print $2 }' "$CG/cpu.stat"
}

TIME_OUT=/tmp/run_measured.time

before_user=$(cpu_usec user_usec)
before_sys=$(cpu_usec system_usec)
/usr/bin/time -f "%M %U %S %e" -o "$TIME_OUT" "$@" >&2
rc=$?
after_user=$(cpu_usec user_usec)
after_sys=$(cpu_usec system_usec)
peak=$(cat "$CG/memory.peak")

# GNU time puts "Command exited with non-zero status N" before the format line on failure.
detail=$(tail -n 1 "$TIME_OUT") || fail "GNU time wrote no output"
rss_kb=${detail%% *}
case "$rss_kb" in
    ''|*[!0-9]*) fail "cannot parse GNU time output: $detail" ;;
esac
if [ -n "${RUN_MEASURED_DETAIL:-}" ]; then
    echo "$detail" > "$RUN_MEASURED_DETAIL" || fail "cannot write $RUN_MEASURED_DETAIL"
fi

echo "$rc,$((after_user - before_user)),$((after_sys - before_sys)),$peak,$((rss_kb * 1024))"
