#!/usr/bin/env python3
"""Builds the two results figures of the ICPE paper from the bench's score files.

  verdicts.pdf       what each system answered, on pairs where the symptom is present
                     and on pairs where it is absent (run 1, both wordings)
  time_accuracy.pdf  median time per answer against balanced accuracy

Run from anywhere: python3 make_result_figures.py
Codex is included once results/codex/run1_scores.csv exists.
"""
import csv, glob, json, statistics
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
RES = HERE.parents[1] / "bench" / "results"

SYSTEMS = [  # (label, scores csv, answers folder)
    ("LLM only", RES / "llm_only/run1_scores.csv", RES / "llm_only/run1"),
    ("RAG", RES / "rag/run1_scores.csv", RES / "rag/run1"),
    ("TMLL", RES / "tmll/run1_scores.csv", RES / "tmll/run1"),
    ("Codex", RES / "codex/run1_scores.csv", RES / "codex/run1"),
    ("TraceAssist", RES / "traceassist/run1_scores.csv", RES / "traceassist/run1"),
]

# Palette: dataviz reference instance, light mode (validated: blue/orange pass all checks).
SURFACE, INK, INK2, MUTED, GRID = "#ffffff", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
YES, NO, CANT = "#2a78d6", "#eb6834", "#c3c2b7"

plt.rcParams.update({
    "font.family": "sans-serif", "font.size": 7, "axes.edgecolor": "#c3c2b7",
    "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "pdf.fonttype": 42, "ps.fonttype": 42,
})


def load(csv_path):
    rows = list(csv.DictReader(open(csv_path)))
    c = {}
    for r in rows:
        c[r["outcome"]] = c.get(r["outcome"], 0) + 1
    return c


def median_seconds(folder):
    e = [json.load(open(f)).get("elapsed_s") for f in glob.glob(str(folder / "*.json"))]
    return statistics.median([x for x in e if x])


data = []
for label, path, folder in SYSTEMS:
    if not path.exists():
        continue
    c = load(path)
    tp, fn, fnc = c.get("TP", 0), c.get("FN", 0), c.get("FN_cautious", 0)
    fp, tn, tna = c.get("FP", 0), c.get("TN", 0), c.get("TN_abstain", 0)
    recall = tp / (tp + fn + fnc)
    spec = (tn + tna) / (tn + tna + fp)
    data.append(dict(label=label, present=(tp, fn, fnc), absent=(fp, tn, tna),
                     bal=(recall + spec) / 2, secs=median_seconds(folder)))

# ---- Figure: verdict shares ------------------------------------------------
fig, axes = plt.subplots(2, 1, figsize=(3.33, 2.55), sharex=True,
                         gridspec_kw=dict(hspace=0.55))
panels = [("present", "Symptom present: “yes” is right"),
          ("absent", "Symptom absent: “no” is right")]
labels = [d["label"] for d in data][::-1]
for ax, (key, title) in zip(axes, panels):
    n = sum(data[0][key])
    ax.set_title(f"{title} ({n} answers per system)", loc="left", fontsize=7, color=INK, pad=3)
    for i, d in enumerate(data[::-1]):
        vals = [v / sum(d[key]) * 100 for v in d[key]]
        left = 0
        for v, col in zip(vals, (YES, NO, CANT)):
            ax.barh(i, v, left=left, height=0.62, color=col, edgecolor=SURFACE, linewidth=0.8)
            if v >= 9:
                ax.text(left + v / 2, i, f"{v:.0f}", ha="center", va="center", fontsize=6,
                        color=INK if col == CANT else "#ffffff")
            left += v
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlim(0, 100)
    ax.tick_params(length=0)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
axes[1].set_xlabel("Share of answers (%)", fontsize=7)
handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in (YES, NO, CANT)]
fig.legend(handles, ["yes", "no", "cannot tell"], loc="upper center", ncol=3, frameon=False,
           fontsize=7, bbox_to_anchor=(0.55, 1.03), handlelength=1.2, columnspacing=1.2)
fig.savefig(HERE / "verdicts.pdf", bbox_inches="tight", pad_inches=0.02)

# ---- Figure: time against balanced accuracy ---------------------------------
fig, ax = plt.subplots(figsize=(3.33, 1.85))
ax.set_xscale("log")
ax.set_xlim(8, 500)
ax.set_ylim(0.5, 1.0)
ax.grid(True, which="major", axis="y", color=GRID, linewidth=0.5)
ax.set_axisbelow(True)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
merged = {}
for d in data:
    key = (round(d["bal"], 2), round(d["secs"]))
    merged.setdefault(round(d["bal"], 2), []).append(d)
for d in data:
    col = YES if d["label"] == "TraceAssist" else INK2
    ax.scatter(d["secs"], d["bal"], s=26, color=col, edgecolor=SURFACE, linewidth=1, zorder=3)
done = set()
for d in data:
    same = [e for e in data if abs(e["bal"] - d["bal"]) < 0.01 and abs(e["secs"] - d["secs"]) / d["secs"] < 0.3]
    names = " and ".join(e["label"] for e in same)
    if names in done:
        continue
    done.add(names)
    ax.annotate(f"{names}  {d['bal']:.2f}", (d["secs"], d["bal"]), xytext=(6, 0),
                textcoords="offset points", va="center", fontsize=6.5, color=INK)
ax.set_xticks([10, 30, 100, 300], ["10", "30", "100", "300"])
ax.minorticks_off()
ax.set_xlabel("Median time per answer (s, log scale)")
ax.set_ylabel("Balanced accuracy")
fig.savefig(HERE / "time_accuracy.pdf", bbox_inches="tight", pad_inches=0.02)

for d in data:
    print(f"{d['label']:12} bal {d['bal']:.3f}  median {d['secs']:.1f} s  present {d['present']}  absent {d['absent']}")
