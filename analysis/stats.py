"""Statistics for RQ2 and RQ3: median and IQR, PQ/classical ratios, cost decomposition.

Used by figures.py and tables.py; nothing here reads or writes files. Inputs are the
per-run DataFrames from data.py (one row per run).
- summarize(): median, Q1, Q3, and IQR per measured condition.
- ratios(): median(PQ) / median(classical) within the same tool, file size, number of
  recipients, operation, and position, with a 95% percentile bootstrap CI (the runs of
  each mode resampled independently, 10,000 iterations, fixed seed).
- decompose(): per mode and operation, the least-squares fit
  value = a + b * n_recipients + c * file_bytes over all runs.
"""

import numpy as np
import pandas as pd

import data

KEYS = ["mode", "size_id", "file_bytes", "n_recipients", "op", "recipient_position"]
BOOTSTRAP_ITERATIONS = 10_000
BOOTSTRAP_SEED = 20261031  # fixed, so the CIs are reproducible
CI = 0.95


def summarize(df, value):
    """Median, Q1, Q3, IQR, and run count of value per measured condition."""
    g = df.groupby(KEYS, sort=False)[value]
    out = pd.DataFrame({"median": g.median(), "q1": g.quantile(0.25), "q3": g.quantile(0.75),
                        "n_runs": g.size()}).reset_index()
    out["iqr"] = out["q3"] - out["q1"]
    return out


def bootstrap_ratio(pq, classical, rng, iterations=BOOTSTRAP_ITERATIONS):
    """median(pq) / median(classical) and its percentile bootstrap CI."""
    pq, classical = np.asarray(pq, float), np.asarray(classical, float)
    point = np.median(pq) / np.median(classical)
    pq_s = np.median(rng.choice(pq, (iterations, len(pq))), axis=1)
    cl_s = np.median(rng.choice(classical, (iterations, len(classical))), axis=1)
    lo, hi = np.quantile(pq_s / cl_s, [(1 - CI) / 2, 1 - (1 - CI) / 2])
    return point, lo, hi


def ratios(df, value):
    """PQ/classical ratio of value per tool and matched condition, with bootstrap CI."""
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    match = ["size_id", "file_bytes", "n_recipients", "op", "recipient_position"]
    rows = []
    for tool, (pq_mode, cl_mode) in data.PAIRS.items():
        pq = df[df["mode"] == pq_mode].groupby(match)[value]
        cl = df[df["mode"] == cl_mode].groupby(match)[value]
        cl_groups = dict(list(cl))
        for key, pq_values in pq:
            if key not in cl_groups:
                continue
            point, lo, hi = bootstrap_ratio(pq_values, cl_groups[key], rng)
            rows.append({"tool": tool, **dict(zip(match, key)), "ratio": point,
                         "ci_low": lo, "ci_high": hi,
                         "n_pq": len(pq_values), "n_classical": len(cl_groups[key])})
    return pd.DataFrame(rows)


def decompose(df, value):
    """value ~ a + b * n_recipients + c * file_bytes, per mode and operation/position.

    Decryption is fitted separately for the first and the last recipient (n=1 counts as
    both), because age's cost depends on the position. Returns a, b, c, R^2, and the
    number of runs per fit.
    """
    variants = {"encrypt": lambda d: d["op"] == "encrypt",
                "decrypt_first": lambda d: d["recipient_position"].isin(["only", "first"]),
                "decrypt_last": lambda d: d["recipient_position"].isin(["only", "last"])}
    rows = []
    for mode in data.MODES:
        for variant, select in variants.items():
            d = df[(df["mode"] == mode) & select(df)]
            if d["n_recipients"].nunique() < 2 or d["file_bytes"].nunique() < 2:
                continue
            x = np.column_stack([np.ones(len(d)), d["n_recipients"], d["file_bytes"]])
            y = d[value].to_numpy(float)
            coef, *_ = np.linalg.lstsq(x, y, rcond=None)
            residual = y - x @ coef
            r2 = 1 - residual @ residual / ((y - y.mean()) @ (y - y.mean()))
            rows.append({"mode": mode, "variant": variant, "a": coef[0], "b_per_recipient": coef[1],
                         "c_per_byte": coef[2], "r2": r2, "n_runs": len(d)})
    return pd.DataFrame(rows)
