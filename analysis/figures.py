"""Make every figure for RQ1-RQ3 from results/ (vector PDFs for the IEEE paper).

Runs on the host, after analysis/sanity.py:
    python3 analysis/figures.py [--phase full|pilot] [--results DIR] [--out DIR] [--allow-missing]

Reads only the results directory, writes figures/<name>.pdf:
- overhead_vs_recipients: ciphertext overhead vs. number of recipients (RQ1)
- time_vs_size: encryption and decryption time vs. file size, n=1, log-log (RQ2)
- time_ratio: PQ/classical wall-time ratio with 95% bootstrap CI per condition (RQ2)
- decrypt_position: decryption time as first vs. last of 50 recipients (RQ2)
- resources_vs_recipients: CPU time, max RSS, and cgroup peak memory vs. recipients (RQ3)
Values are medians, error bars the IQR. A figure whose data is missing fails the run,
unless --allow-missing (for development on partial data).
"""

import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter  # noqa: E402

import data  # noqa: E402
import stats  # noqa: E402

# Okabe-Ito colors, validated as a categorical palette (CVD-safe adjacent pairs). The light
# hue is the classical mode, the dark hue the PQ mode of the same tool. Line style and
# marker carry the same identity, so no figure depends on color alone.
STYLE = {
    "age-x25519": {"color": "#56B4E9", "linestyle": "--", "marker": "o"},
    "age-pq": {"color": "#0072B2", "linestyle": "-", "marker": "o"},
    "gpg-cv25519": {"color": "#E69F00", "linestyle": "--", "marker": "s"},
    "gpg-pqc": {"color": "#D55E00", "linestyle": "-", "marker": "s"},
}
INK = "#333333"
GRID = "#dddddd"
BASELINE_COLOR = "#888888"
SINGLE = 3.5   # IEEE column width, inches
DOUBLE = 7.16  # IEEE page width, inches

plt.rcParams.update({
    "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "lines.linewidth": 1.2, "lines.markersize": 4,
    "axes.edgecolor": INK, "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5,
    "axes.spines.top": False, "axes.spines.right": False,
    "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})


def legend_handles(modes=data.MODES):
    return [Line2D([], [], label=m, **STYLE[m]) for m in modes]


def add_legend(fig, modes=data.MODES, ncol=None):
    fig.legend(handles=legend_handles(modes), loc="upper center", ncol=ncol or len(modes),
               frameon=False, bbox_to_anchor=(0.5, 1.02))


def plain_log(ax, axis="y"):
    """Log scale with plain number labels (0.5, 1, 2, 5, ...) instead of powers of ten."""
    target = ax.yaxis if axis == "y" else ax.xaxis
    (ax.set_yscale if axis == "y" else ax.set_xscale)("log")
    target.set_major_locator(LogLocator(base=10, subs=(1, 2, 5)))
    target.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    target.set_minor_formatter(NullFormatter())


def size_axis(ax, phase):
    """Log x axis with one tick per file size of the phase, labelled by size_id."""
    size_ids = data.phase_sizes(phase)
    ticks = [data.SIZES[s] for s in size_ids]
    ax.set_xscale("log")
    ax.set_xlim(ticks[0] / 2, ticks[-1] * 2)
    ax.set_xticks(ticks, size_ids)
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.set_xlabel("file size")


def plot_mode(ax, summary, x, mode, scale=1.0):
    """One mode's medians with IQR error bars against column x."""
    s = summary[summary["mode"] == mode].sort_values(x)
    if s.empty:
        return
    med = s["median"] * scale
    err = [(s["median"] - s["q1"]) * scale, (s["q3"] - s["median"]) * scale]
    ax.errorbar(s[x], med, yerr=err, capsize=2, elinewidth=0.8, **STYLE[mode])


def recipients_axis(ax):
    ax.set_xscale("log")
    ax.set_xticks(data.RECIPIENT_COUNTS, [str(n) for n in data.RECIPIENT_COUNTS])
    ax.minorticks_off()
    ax.set_xlabel("recipients")


def overhead_vs_recipients(results, phase):
    df = data.sizes(results)
    size_id = data.phase_sizes(phase)[0]  # smallest file: isolates the per-recipient overhead
    df = df[df["size_id"] == size_id]
    fig, ax = plt.subplots(figsize=(SINGLE, 2.4))
    for mode in data.MODES:
        s = df[df["mode"] == mode].sort_values("n_recipients")
        ax.plot(s["n_recipients"], s["overhead_bytes"] / 1024, **STYLE[mode])
    recipients_axis(ax)
    plain_log(ax)
    ax.set_ylabel(f"ciphertext overhead (KiB), {size_id} file")
    add_legend(fig, ncol=2)
    fig.tight_layout(rect=(0, 0, 1, 0.88))
    return fig


def time_vs_size(results, phase):
    summary = stats.summarize(data.timing(results, phase), "wall_s")
    summary = summary[summary["n_recipients"] == 1]
    fig, axes = plt.subplots(2, 2, figsize=(DOUBLE, 4.2), sharex=True)
    for col, (tool, modes) in enumerate(data.PAIRS.items()):
        for row, op in enumerate(("encrypt", "decrypt")):
            ax = axes[row][col]
            for mode in reversed(modes):
                plot_mode(ax, summary[summary["op"] == op], "file_bytes", mode, scale=1000)
            size_axis(ax, phase)
            plain_log(ax)
            ax.set_title(f"{tool}, {op}, 1 recipient")
            ax.set_ylabel("wall time (ms)")
            if row == 0:
                ax.set_xlabel("")
    add_legend(fig)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    return fig


def ratio_label(row):
    what = row["op"] if row["op"] == "encrypt" else f"decrypt {row['recipient_position']}"
    return f"{row['size_id']}, n={row['n_recipients']}, {what}"


def time_ratio(results, phase):
    r = stats.ratios(data.timing(results, phase), "wall_s")
    order = {s: i for i, s in enumerate(data.SIZES)}
    pos = {"na": 0, "only": 1, "first": 1, "last": 2}
    r = r.assign(o1=r["size_id"].map(order), o2=r["op"].map({"encrypt": 0, "decrypt": 1}),
                 o3=r["recipient_position"].map(pos))
    r = r.sort_values(["o1", "n_recipients", "o2", "o3"])
    labels = list(dict.fromkeys(r.apply(ratio_label, axis=1)))
    fig, axes = plt.subplots(1, 2, figsize=(DOUBLE, 0.16 * len(labels) + 0.8), sharey=True)
    for ax, (tool, (pq_mode, _)) in zip(axes, data.PAIRS.items()):
        t = r[r["tool"] == tool]
        y = [labels.index(ratio_label(row)) for _, row in t.iterrows()]
        ax.errorbar(t["ratio"], y, xerr=[t["ratio"] - t["ci_low"], t["ci_high"] - t["ratio"]],
                    fmt=STYLE[pq_mode]["marker"], color=STYLE[pq_mode]["color"],
                    capsize=1.5, elinewidth=0.8)
        ax.axvline(1, color=INK, linewidth=0.6)
        plain_log(ax, "x")
        ax.set_title(f"{tool}: {pq_mode} / {data.PAIRS[tool][1]}")
        ax.set_xlabel("wall-time ratio (median, 95% CI)")
    axes[0].set_yticks(range(len(labels)), labels)
    axes[0].invert_yaxis()
    fig.tight_layout()
    return fig


def decrypt_position(results, phase):
    summary = stats.summarize(data.timing(results, phase), "wall_s")
    summary = summary[(summary["n_recipients"] == 50) & (summary["op"] == "decrypt")]
    size_ids = data.phase_sizes(phase)
    fig, axes = plt.subplots(1, len(size_ids), figsize=(DOUBLE, 2.2), squeeze=False)
    for ax, size_id in zip(axes[0], size_ids):
        s = summary[summary["size_id"] == size_id]
        for i, mode in enumerate(data.MODES):
            for j, position in enumerate(("first", "last")):
                row = s[(s["mode"] == mode) & (s["recipient_position"] == position)]
                if row.empty:
                    continue
                row = row.iloc[0]
                x = i + (j - 0.5) * 0.36
                ax.bar(x, row["median"] * 1000, width=0.34, color=STYLE[mode]["color"],
                       hatch=None if position == "first" else "////", edgecolor="white",
                       linewidth=0.5, yerr=[[(row["median"] - row["q1"]) * 1000],
                                            [(row["q3"] - row["median"]) * 1000]],
                       error_kw={"elinewidth": 0.8, "capsize": 1.5, "ecolor": INK})
        ax.set_xticks(range(len(data.MODES)), data.MODES, rotation=30, ha="right")
        ax.set_title(f"{size_id}, 50 recipients")
        ax.grid(axis="x", visible=False)
    axes[0][0].set_ylabel("decryption wall time (ms)")
    fig.legend(handles=[plt.Rectangle((0, 0), 1, 1, facecolor=BASELINE_COLOR, label="first (r01)"),
                        plt.Rectangle((0, 0), 1, 1, facecolor=BASELINE_COLOR, hatch="////",
                                      edgecolor="white", label="last (r50)")],
               loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.04))
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    return fig


RESOURCE_METRICS = (("cpu_usec", "CPU time (ms)", 1e-3),
                    ("max_rss_bytes", "max RSS (MiB)", 1 / 2**20),
                    ("mem_peak_bytes", "cgroup peak (MiB)", 1 / 2**20))


def resources_vs_recipients(results, phase):
    df = data.resources(results, phase)
    base = data.baseline(results, phase)
    df = df[df["op"] == "encrypt"]
    size_ids = data.phase_sizes(phase)
    fig, axes = plt.subplots(len(RESOURCE_METRICS), len(size_ids), squeeze=False,
                             figsize=(DOUBLE, 1.7 * len(RESOURCE_METRICS) + 0.4), sharex=True)
    for col, size_id in enumerate(size_ids):
        d = df[df["size_id"] == size_id]
        for row, (metric, label, scale) in enumerate(RESOURCE_METRICS):
            ax = axes[row][col]
            summary = stats.summarize(d, metric)
            for mode in data.MODES:
                plot_mode(ax, summary, "n_recipients", mode, scale)
            if not base.empty:
                ax.axhline(base[metric].median() * scale, color=BASELINE_COLOR, linestyle=":",
                           linewidth=0.8)
            ax.set_ylim(bottom=0)
            recipients_axis(ax)
            if row == 0:
                ax.set_title(f"encrypt, {size_id}")
            if col == 0:
                ax.set_ylabel(label)
            if row < len(RESOURCE_METRICS) - 1:
                ax.set_xlabel("")
    handles = legend_handles() + [Line2D([], [], color=BASELINE_COLOR, linestyle=":",
                                         label="baseline (true)")]
    fig.legend(handles=handles, loc="upper center", ncol=len(handles), frameon=False,
               bbox_to_anchor=(0.5, 1.01))
    fig.tight_layout(rect=(0, 0, 1, 0.96))
    return fig


FIGURES = {
    "overhead_vs_recipients": overhead_vs_recipients,
    "time_vs_size": time_vs_size,
    "time_ratio": time_ratio,
    "decrypt_position": decrypt_position,
    "resources_vs_recipients": resources_vs_recipients,
}


def run(phase="full", results=data.RESULTS, out=data.FIGURES, allow_missing=False, only=None):
    """Write every figure; return False if one could not be made."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    ok = True
    for name, make in FIGURES.items():
        if only and name not in only:
            continue
        try:
            fig = make(results, phase)
        except data.DataError as e:
            print(f"{'SKIP' if allow_missing else 'FAIL'}  {name}: {e}")
            ok = ok and allow_missing
            continue
        fig.savefig(out / f"{name}.pdf")
        plt.close(fig)
        print(f"wrote {out / name}.pdf")
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phase", choices=("full", "pilot"), default="full")
    parser.add_argument("--results", default=str(data.RESULTS))
    parser.add_argument("--out", default=str(data.FIGURES))
    parser.add_argument("--allow-missing", action="store_true",
                        help="skip figures whose data is missing (development only)")
    parser.add_argument("--only", nargs="+", choices=sorted(FIGURES))
    args = parser.parse_args()
    sys.exit(0 if run(args.phase, args.results, args.out, args.allow_missing, args.only) else 1)


if __name__ == "__main__":
    main()
