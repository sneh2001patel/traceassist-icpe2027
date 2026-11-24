#!/usr/bin/env python3
"""Checks that this repository holds the TraceAssist that produced the paper's results.

Every saved TraceAssist answer records two fingerprints (see bench/run_traceassist.py):
  build           sha256 over the installed server bundle, every skill file, and the TMLL
                  service's Python code (tmll/*.py, tmll/rag/*.py)
  knowledge base  sha256 over the RAG documents TraceAssist retrieves from (tmll/rag/knowledge)
This script recomputes both from the files in this repository, checks that the launcher jar
carries the same bundle, and checks that every answer in bench/results/traceassist has them.
No network, no API key.  Usage: python3 verify_frozen.py
"""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = "a4162fd526b12d22"
KNOWLEDGE = "1d7092adf385d1ab"
BUNDLE_NAME = "org.eclipse.tracecompass.traceassist.server_0.1.0.jar"
BUNDLE = ROOT / "traceassist" / "dist" / BUNDLE_NAME
LAUNCHER = ROOT / "traceassist" / "dist" / "traceassist-server.jar"
SKILLS = ROOT / "traceassist" / "plugin" / "skills"
TMLL = ROOT / "tmll"

sys.path.insert(0, str(ROOT / "bench"))
import run_traceassist  # noqa: E402  (the fingerprints are computed by the same code as the runs)

run_traceassist.BUNDLE, run_traceassist.SKILLS, run_traceassist.TMLL = BUNDLE, SKILLS, TMLL
ok = True


def check(label, good, detail=""):
    global ok
    ok &= good
    print(f"{'ok  ' if good else 'FAIL'} {label}{(': ' + detail) if detail else ''}")


build = run_traceassist.build_fingerprint()
check("build fingerprint", build == BUILD, f"{build} (expected {BUILD})")
kb = run_traceassist.knowledge_fingerprint()
check("knowledge base fingerprint", kb == KNOWLEDGE, f"{kb} (expected {KNOWLEDGE})")

with zipfile.ZipFile(LAUNCHER) as jar:
    inner = hashlib.sha256(jar.read(f"bundle/{BUNDLE_NAME}")).hexdigest()
check("launcher jar carries the same bundle", inner == hashlib.sha256(BUNDLE.read_bytes()).hexdigest())

for run in (1, 2, 3):
    answers = sorted((ROOT / "bench" / "results" / "traceassist" / f"run{run}").glob("*.json"))
    builds = {json.loads(a.read_text()).get("build") for a in answers}
    check(f"results/traceassist/run{run}", len(answers) == 516 and builds == {BUILD},
          f"{len(answers)} answers, builds {sorted(b for b in builds if b)}")

print("frozen version verified" if ok else "NOT the frozen version")
sys.exit(0 if ok else 1)
