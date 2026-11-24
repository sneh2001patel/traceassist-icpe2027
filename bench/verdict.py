"""The verdict line: the one instruction every system under test gets with every question,
and the parser that reads the verdict back.

Every bench question asks whether a symptom is there ("Does ...? If so, ..."). To grade the
answer as a TP, FP, TN or FN without relying on a judge's reading of the prose, the same
sentence is added to every question, for TraceAssist and for every baseline alike:

    <question>

    Begin your answer with exactly one line: "Verdict: yes", "Verdict: no", or
    "Verdict: cannot tell from this trace". Then answer the question.

"yes" means the symptom is present, "no" that it is absent, and "cannot tell" that the trace
cannot establish it. The LLM judge then checks only what the verdict line cannot: the
location, the numbers, the fix, and whether the prose contradicts the line.
"""

from __future__ import annotations

import re

INSTRUCTION = ('Begin your answer with exactly one line: "Verdict: yes", "Verdict: no", or '
               '"Verdict: cannot tell from this trace". Then answer the question.')


def prompt(question_text: str) -> str:
    """The text sent to a system under test for one bench question."""
    return f"{question_text}\n\n{INSTRUCTION}"


# The first "Verdict:" line, allowing Markdown decoration such as "**Verdict: yes**" or
# "## Verdict: no", and a trailing full stop or explanation.
_LINE = re.compile(r"^[\s>#*_`-]*verdict\s*[:\-]\s*[*_`]*\s*(yes|no|cannot tell|can't tell|"
                   r"can not tell|unknown|unclear)\b", re.IGNORECASE | re.MULTILINE)

VERDICTS = {"yes": "present", "no": "absent"}


def parse(answer: str) -> dict:
    """Reads the verdict from an answer.

    Returns {"verdict": "present" | "absent" | "cannot_tell" | None, "position": "first" |
    "later" | None, "line": the matched line}. "later" means the line was not the answer's
    first non-empty line: the verdict still counts, and the grade notes the format slip.
    None means no verdict line; the grader then falls back to the judge's reading.
    """
    match = _LINE.search(answer or "")
    if not match:
        return {"verdict": None, "position": None, "line": None}
    word = match.group(1).lower()
    verdict = VERDICTS.get(word, "cannot_tell")
    first = next((l for l in (answer or "").splitlines() if l.strip()), "")
    line = answer[match.start():].splitlines()[0].strip()
    return {"verdict": verdict, "position": "first" if first.strip() == line else "later",
            "line": line}


if __name__ == "__main__":
    tests = {
        "Verdict: yes\nworker-2 waits": "present",
        "**Verdict: no**\n\nNothing found.": "absent",
        "## Verdict: cannot tell from this trace": "cannot_tell",
        "Some preamble\nVerdict: Yes. The flusher...": "present",
        "verdict - no": "absent",
        "No verdict here": None,
    }
    for text, want in tests.items():
        got = parse(text)["verdict"]
        assert got == want, (text, got, want)
    assert parse("Some preamble\nVerdict: yes")["position"] == "later"
    print("verdict.py: all parser checks pass")
