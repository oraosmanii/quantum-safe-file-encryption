"""Check the raw results before any figure is made; fail loudly on anything incomplete.

Runs on the host:
    python3 analysis/sanity.py [--phase full|pilot] [--results DIR]

Checks, per results file:
- the file exists and its header matches data.HEADERS;
- every expected condition (all 128 measured conditions for timing and resources, all
  48 conditions for sizes, 50 keys per mode) is present with exactly runs 1..N;
- every exit code is 0 and every sha256_ok is true;
- no unknown condition, mode, or size appears.
It also flags noisy conditions, whose IQR is more than 20% of the median: A reruns noisy
timing conditions, C noisy resource conditions. Flags are warnings, not failures.
Exits 1 if any check fails. An interop failure is a result, not a sanity failure:
matrix.csv is only checked for completeness.
"""

import argparse
import sys

import data

NOISE_LIMIT = 0.20


class Report:
    def __init__(self):
        self.failures = []
        self.warnings = []

    def fail(self, name, message):
        self.failures.append(f"{name}: {message}")

    def warn(self, name, message):
        self.warnings.append(f"{name}: {message}")

    def check(self, name, load):
        """load() the file; record a failure and return None if it cannot be read."""
        try:
            return load()
        except data.DataError as e:
            self.fail(name, str(e))
        except ValueError as e:
            self.fail(name, f"unreadable value: {e}")
        return None


def check_runs(report, name, df, phase):
    """Every measured condition with runs 1..N exactly once, nothing else."""
    expected = {c.condition_id: n for c, n in data.expected_conditions(phase)}
    found = df.groupby("condition_id")["run"].apply(sorted).to_dict()
    missing = sorted(set(expected) - set(found))
    if missing:
        report.fail(name, f"{len(missing)} of {len(expected)} measured conditions missing, "
                          f"e.g. {', '.join(missing[:3])}")
    unknown = sorted(set(found) - set(expected))
    if unknown:
        report.fail(name, f"unknown conditions: {', '.join(unknown[:5])}")
    for cid, runs in sorted(found.items()):
        if cid in expected and runs != list(range(1, expected[cid] + 1)):
            report.fail(name, f"{cid}: runs {runs}, expected 1..{expected[cid]}")


def check_valid(report, name, df):
    bad = df[df["exit_code"] != 0]
    if len(bad):
        report.fail(name, f"{len(bad)} rows with a non-zero exit code, e.g. "
                          f"{bad['condition_id'].iloc[0]} run {bad['run'].iloc[0]}")
    bad = df[df["sha256_ok"] != "true"]
    if len(bad):
        report.fail(name, f"{bad['condition_id'].nunique()} conditions with sha256_ok != true, "
                          f"e.g. {bad['condition_id'].iloc[0]}")


def flag_noisy(report, name, df, column):
    q = df.groupby("condition_id")[column].quantile([0.25, 0.5, 0.75]).unstack()
    noisy = q[(q[0.75] - q[0.25]) > NOISE_LIMIT * q[0.5]]
    for cid, row in noisy.iterrows():
        report.warn(name, f"noisy {column}: {cid} IQR {row[0.75] - row[0.25]:.4g} "
                          f"> 20% of median {row[0.5]:.4g}")


def check_key_sizes(report, results):
    name = "key_sizes.csv"
    df = report.check(name, lambda: data.key_sizes(results))
    if df is None:
        return
    counts = df.groupby("mode").size().reindex(data.MODES, fill_value=0)
    for mode, n in counts.items():
        if n != data.conditions.N_KEYS:
            report.fail(name, f"{mode}: {n} keys, expected {data.conditions.N_KEYS}")
    if set(df["mode"]) - set(data.MODES):
        report.fail(name, f"unknown modes: {sorted(set(df['mode']) - set(data.MODES))}")
    # Sizes should not vary within a mode; gpg certs may differ by 1 byte.
    for mode, g in df.groupby("mode"):
        spread = g["public_key_bytes"].max() - g["public_key_bytes"].min()
        if spread > 1:
            report.fail(name, f"{mode}: public_key_bytes varies by {spread} bytes")
        elif spread == 1:
            report.warn(name, f"{mode}: public_key_bytes varies by 1 byte (MPI encoding)")


def check_sizes(report, results, phase):
    name = "sizes.csv"
    df = report.check(name, lambda: data.sizes(results))
    if df is None:
        return
    df = df[df["size_id"].isin(data.phase_sizes(phase))]
    keys = df[["mode", "size_id", "n_recipients"]].apply(tuple, axis=1)
    expected = {(m, s, n) for m in data.MODES for s in data.phase_sizes(phase)
                for n in data.RECIPIENT_COUNTS}
    missing = expected - set(keys)
    if missing:
        report.fail(name, f"{len(missing)} of {len(expected)} conditions missing, e.g. {sorted(missing)[0]}")
    if keys.duplicated().any():
        report.fail(name, f"duplicate conditions: {sorted(set(keys[keys.duplicated()]))[:3]}")
    if (df["sha256_ok"] != "true").any():
        report.fail(name, f"{(df['sha256_ok'] != 'true').sum()} rows with sha256_ok != true")
    wrong = df[df["overhead_bytes"] != df["ciphertext_bytes"] - df["file_bytes"]]
    if len(wrong):
        report.fail(name, f"{len(wrong)} rows where overhead_bytes != ciphertext_bytes - file_bytes")


def check_timing(report, results, phase):
    name = "timing.csv"
    df = report.check(name, lambda: data.timing(results, phase))
    if df is None:
        return
    check_runs(report, name, df, phase)
    check_valid(report, name, df)
    flag_noisy(report, name, df, "wall_s")


def check_resources(report, results, phase):
    name = "resources.csv"
    df = report.check(name, lambda: data.resources(results, phase))
    if df is not None:
        check_runs(report, name, df, phase)
        check_valid(report, name, df)
        for column in ("cpu_usec", "max_rss_bytes", "mem_peak_bytes"):
            flag_noisy(report, name, df, column)
    name = "resources_baseline.csv"
    df = report.check(name, lambda: data.baseline(results, phase))
    if df is None:
        return
    runs = data.conditions.PILOT_RUNS if phase == "pilot" else 10
    if sorted(df["run"]) != list(range(1, runs + 1)):
        report.fail(name, f"runs {sorted(df['run'])}, expected 1..{runs}")
    if (df["exit_code"] != 0).any():
        report.fail(name, "baseline run with a non-zero exit code")


def check_matrix(report, results, phase):
    name = "matrix.csv"
    df = report.check(name, lambda: data.matrix(results))
    if df is None:
        return
    repeats = 3 if phase == "full" else 1
    expected = 3 * 3 * 2 * repeats  # encryptor x decryptor x key_type x repeat
    cells = df[["repeat", "encryptor", "decryptor", "key_type"]].drop_duplicates()
    if len(cells) < expected:
        report.fail(name, f"{len(cells)} cells, expected {expected}")
    if len(df) != len(cells):
        report.fail(name, f"{len(df) - len(cells)} duplicate cells")
    bad = df[~df["result"].isin(["pass", "fail"])]
    if len(bad):
        report.fail(name, f"{len(bad)} rows with result not pass/fail")


def check_env(report, results):
    name = "env.json"
    env = report.check(name, lambda: data.env(results))
    if env is None:
        return
    for key in ("captured_utc", "git_commit", "host", "docker", "container", "tools"):
        if key not in env:
            report.fail(name, f"key {key} missing")


CHECKS = ("key_sizes", "sizes", "timing", "resources", "matrix", "env")


def run(phase="full", results=data.RESULTS, only=None):
    """Run the checks; print the report; return True if nothing failed."""
    report = Report()
    selected = only or CHECKS
    if "key_sizes" in selected:
        check_key_sizes(report, results)
    if "sizes" in selected:
        check_sizes(report, results, phase)
    if "timing" in selected:
        check_timing(report, results, phase)
    if "resources" in selected:
        check_resources(report, results, phase)
    if "matrix" in selected:
        check_matrix(report, results, phase)
    if "env" in selected:
        check_env(report, results)

    for line in report.warnings:
        print(f"WARN  {line}")
    for line in report.failures:
        print(f"FAIL  {line}")
    print(f"sanity ({phase}, {', '.join(selected)}): {len(report.failures)} failures, "
          f"{len(report.warnings)} warnings")
    return not report.failures


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phase", choices=("full", "pilot"), default="full")
    parser.add_argument("--results", default=str(data.RESULTS), help="results directory")
    parser.add_argument("--only", nargs="+", choices=CHECKS, help="run only these checks")
    args = parser.parse_args()
    sys.exit(0 if run(args.phase, args.results, args.only) else 1)


if __name__ == "__main__":
    main()
