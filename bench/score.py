#!/usr/bin/env python3
"""Scores a system's saved answers from their verdict lines: TP, FP, TN, FN and the metrics in
the report (section "Grading" and "Metrics"). No API calls.

    python3 score.py                          # traceassist, run 1, every saved answer
    python3 score.py --system traceassist --run 1 --v1
    python3 score.py --csv out.csv            # also write one row per answer

How a verdict is classified (the report's outcome table):

    truth \\ verdict   present            absent              cannot tell
    present           TP                 FN                  FN (too cautious)
    absent            FP (hallucination) TN                  TN, also an abstention
    cannot be seen    FP                 wrong (claims an    correct
                                         absence it can't see)
    don't care        not graded

An answer without a verdict line is counted separately ("no verdict") and left out of the
counts; the LLM judge reads those. Location, numbers and fixes are the judge's part, not this
script's. Consistency needs runs 2 and 3; wording sensitivity compares wordings a and b.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent


def outcome(truth: str, verdict: str | None) -> str:
    if verdict is None:
        return "no_verdict"
    if truth == "present":
        return {"present": "TP", "absent": "FN", "cannot_tell": "FN_cautious"}[verdict]
    if truth == "absent":
        return {"present": "FP", "absent": "TN", "cannot_tell": "TN_abstain"}[verdict]
    if truth == "cannot_see":
        return {"present": "FP_unseeable", "absent": "wrong_unseeable", "cannot_tell": "correct_unseeable"}[verdict]
    return "dont_care"


def metrics(outcomes: list[str]) -> dict:
    c = Counter(outcomes)
    tp = c["TP"]
    fn = c["FN"] + c["FN_cautious"]
    fp = c["FP"]
    tn = c["TN"] + c["TN_abstain"]
    div = lambda a, b: a / b if b else None
    precision, recall, specificity = div(tp, tp + fp), div(tp, tp + fn), div(tn, tn + fp)
    f1 = div(2 * precision * recall, precision + recall) if precision and recall else (0.0 if precision == 0 or recall == 0 else None)
    balanced = (recall + specificity) / 2 if recall is not None and specificity is not None else None
    unseeable = c["FP_unseeable"] + c["wrong_unseeable"] + c["correct_unseeable"]
    graded = tp + fn + fp + tn
    return {
        "answers": len(outcomes), "graded": graded, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "precision": precision, "recall": recall, "specificity": specificity, "fp_rate": div(fp, fp + tn),
        "f1": f1, "balanced_accuracy": balanced,
        "abstentions": c["FN_cautious"] + c["TN_abstain"] + c["correct_unseeable"],
        "abstention_rate": div(c["FN_cautious"] + c["TN_abstain"], graded),
        "cannot_see": unseeable, "cannot_see_correct": c["correct_unseeable"],
        "no_verdict": c["no_verdict"],
    }


def fmt(v) -> str:
    return "  -  " if v is None else f"{v:5.2f}" if isinstance(v, float) else f"{v:5d}"


def table(title: str, groups: dict[str, list[str]]) -> None:
    cols = ["graded", "TP", "FN", "FP", "TN", "precision", "recall", "specificity", "f1",
            "balanced_accuracy", "abstention_rate", "no_verdict"]
    heads = ["n", "TP", "FN", "FP", "TN", "prec", "recall", "spec", "F1", "bal.acc", "abst", "noV"]
    print(f"\n{title}")
    print(f"  {'':<26}" + "".join(f"{h:>8}" for h in heads))
    for name, outs in groups.items():
        m = metrics(outs)
        print(f"  {name:<26}" + "".join(f"{fmt(m[c]):>8}" for c in cols))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--system", default="traceassist")
    ap.add_argument("--run", type=int, default=1)
    ap.add_argument("--v1", action="store_true", help="only the 6 symptoms the thread search supports")
    ap.add_argument("--folder", help="score results/<system>/<folder> instead of run<N>")
    ap.add_argument("--csv", help="write one row per answer to this file")
    args = ap.parse_args()

    pairs = {(p["question"], p["run_id"]): p for p in json.loads((HERE / "pairs.json").read_text())["pairs"]}
    groups_of = {s["id"]: s["group"] for s in json.loads((HERE / "symptoms.json").read_text())["symptoms"]}
    folder = HERE / "results" / args.system / (args.folder or f"run{args.run}")
    rows, builds = [], Counter()
    for f in sorted(folder.glob("*.json")):
        r = json.loads(f.read_text())
        if r.get("status") != "ok":
            continue
        qid, run_id = r["question_id"], r["run_id"]
        p = pairs.get((qid[:-1], run_id))
        if p is None or (args.v1 and not p["v1"]):
            continue
        builds[r.get("build")] += 1
        verdict = (r.get("verdict") or {}).get("verdict")
        rows.append({"id": r["id"], "question": qid[:-1], "wording": qid[-1], "run_id": run_id,
                     "symptom": p["symptom"], "group": groups_of[p["symptom"]], "category": p["category"],
                     "hub": p["hub"], "v1": p["v1"], "fault": p["fault"], "truth": p["truth"],
                     "verdict": verdict, "outcome": outcome(p["truth"], verdict),
                     "verdict_position": (r.get("verdict") or {}).get("position")})
    if not rows:
        print(f"no saved answers in {folder}")
        return 1
    print(f"{args.system} run {args.run}: {len(rows)} answers" + (" (v1 symptoms only)" if args.v1 else "")
          + f"; builds: {dict(builds)}")
    if len(builds) > 1:
        print("  WARNING: answers from more than one TraceAssist build are mixed here")
    late = sum(1 for r in rows if r["verdict_position"] == "later")
    if late:
        print(f"  {late} answer(s) put the verdict line after other text")

    out = lambda rs: [r["outcome"] for r in rs]
    by = lambda key: {k: out([r for r in rows if r[key] == k]) for k in sorted({r[key] for r in rows}, key=str)}
    table("All answers", {"all": out(rows), "wording a (precise)": out([r for r in rows if r["wording"] == "a"]),
                          "wording b (everyday)": out([r for r in rows if r["wording"] == "b"])})
    table("By category", by("category"))
    table("By hub scope", by("hub"))
    table("By symptom group", by("group"))
    table("Supported (v1) or not", {("v1 (6 supported)" if k else "other 42"): v for k, v in by("v1").items()})

    # Wording sensitivity: pairs where both wordings were answered and the verdicts differ.
    both = defaultdict(dict)
    for r in rows:
        both[(r["question"], r["run_id"])][r["wording"]] = r["verdict"]
    compared = [v for v in both.values() if "a" in v and "b" in v]
    differ = sum(1 for v in compared if v["a"] != v["b"])
    print(f"\nWording sensitivity: {differ} of {len(compared)} pairs get different verdicts for the two wordings")

    wrong = [r for r in rows if r["outcome"] in ("FP", "FN", "FN_cautious", "FP_unseeable", "wrong_unseeable", "no_verdict")]
    if wrong:
        print("\nErrors:")
        for r in sorted(wrong, key=lambda r: (r["outcome"], r["id"])):
            print(f"  {r['outcome']:<16} {r['id']:<24} {r['symptom']:<26} fault {r['fault']:<20} said {r['verdict']}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
