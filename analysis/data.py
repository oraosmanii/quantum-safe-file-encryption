"""Load the raw results for the analysis: CSV headers checked against HEADERS.

Shared by sanity.py, stats.py, figures.py, and tables.py. Runs on the host with the
pinned packages from requirements.txt. Every function takes the results directory, so
the analysis can be pointed at a copy of results/ (--results) without touching it.
"""

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
import conditions  # noqa: E402  (bench/conditions.py: modes, sizes, measured conditions)

RESULTS = ROOT / "results"
FIGURES = ROOT / "figures"
TABLES = ROOT / "tables"

MODES = conditions.MODES
SIZES = conditions.SIZES
RECIPIENT_COUNTS = conditions.RECIPIENT_COUNTS
# Each post-quantum mode is compared with the classical mode of the same tool.
PAIRS = {"age": ("age-pq", "age-x25519"), "gpg": ("gpg-pqc", "gpg-cv25519")}
PQ_MODES = {pq for pq, _ in PAIRS.values()}

# Exact header rows of every results CSV.
HEADERS = {
    "bench/key_sizes.csv": ["mode", "recipient_id", "public_key_bytes", "enc_subkey_packet_bytes",
                            "tool_version", "timestamp_utc"],
    "bench/sizes.csv": ["mode", "size_id", "file_bytes", "n_recipients", "ciphertext_bytes",
                        "overhead_bytes", "sha256_ok", "tool_version", "timestamp_utc"],
    "bench/timing.csv": ["timestamp_utc", "phase", "condition_id", "mode", "size_id", "file_bytes",
                         "n_recipients", "op", "recipient_position", "run", "wall_s", "exit_code",
                         "sha256_ok", "tool_version", "hyperfine_json"],
    "bench/resources.csv": ["timestamp_utc", "phase", "condition_id", "mode", "size_id",
                            "file_bytes", "n_recipients", "op", "recipient_position", "run",
                            "exit_code", "cpu_user_usec", "cpu_system_usec", "mem_peak_bytes",
                            "max_rss_bytes", "sha256_ok", "tool_version"],
    "bench/resources_baseline.csv": ["timestamp_utc", "phase", "run", "exit_code", "cpu_user_usec",
                                     "cpu_system_usec", "mem_peak_bytes", "max_rss_bytes"],
    "interop/matrix.csv": ["timestamp_utc", "repeat", "encryptor", "decryptor", "key_type",
                           "stage_reached", "result", "exit_code", "error_message",
                           "encryptor_version", "decryptor_version"],
}


class DataError(Exception):
    """A results file is missing or does not match its expected header."""


def read(results, name):
    """One results CSV as a DataFrame, read as strings and checked against its header."""
    p = Path(results) / name
    if not p.is_file():
        raise DataError(f"{name} is missing")
    df = pd.read_csv(p, dtype=str, keep_default_na=False)
    if list(df.columns) != HEADERS[name]:
        raise DataError(f"{name} has header {list(df.columns)}, expected {HEADERS[name]}")
    return df


def _numeric(df, columns):
    for c in columns:
        df[c] = pd.to_numeric(df[c], errors="raise")
    return df


def key_sizes(results=RESULTS):
    df = read(results, "bench/key_sizes.csv")
    df["public_key_bytes"] = pd.to_numeric(df["public_key_bytes"])
    df["enc_subkey_packet_bytes"] = pd.to_numeric(df["enc_subkey_packet_bytes"].replace("", None))
    return df


def sizes(results=RESULTS):
    return _numeric(read(results, "bench/sizes.csv"),
                    ["file_bytes", "n_recipients", "ciphertext_bytes", "overhead_bytes"])


def timing(results=RESULTS, phase="full"):
    df = read(results, "bench/timing.csv")
    df = _numeric(df, ["file_bytes", "n_recipients", "run", "wall_s", "exit_code"])
    return df[df["phase"] == phase].reset_index(drop=True)


def resources(results=RESULTS, phase="full"):
    df = read(results, "bench/resources.csv")
    df = _numeric(df, ["file_bytes", "n_recipients", "run", "exit_code", "cpu_user_usec",
                       "cpu_system_usec", "mem_peak_bytes", "max_rss_bytes"])
    df["cpu_usec"] = df["cpu_user_usec"] + df["cpu_system_usec"]
    return df[df["phase"] == phase].reset_index(drop=True)


def baseline(results=RESULTS, phase="full"):
    df = read(results, "bench/resources_baseline.csv")
    df = _numeric(df, ["run", "exit_code", "cpu_user_usec", "cpu_system_usec",
                       "mem_peak_bytes", "max_rss_bytes"])
    df["cpu_usec"] = df["cpu_user_usec"] + df["cpu_system_usec"]
    return df[df["phase"] == phase].reset_index(drop=True)


def matrix(results=RESULTS):
    return read(results, "interop/matrix.csv")


def env(results=RESULTS):
    p = Path(results) / "env.json"
    if not p.is_file():
        raise DataError("env.json is missing")
    return json.loads(p.read_text(encoding="utf-8"))


def expected_conditions(phase):
    """Every measured condition of the phase with its number of runs."""
    return [(c, conditions.run_count(c, phase)) for c in conditions.conditions(phase)]


def phase_sizes(phase):
    return conditions.PHASE_SIZES[phase]
