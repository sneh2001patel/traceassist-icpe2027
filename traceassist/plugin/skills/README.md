# TraceAssist AI skills

Each AI skill is one decision that TraceAssist delegates to a language model. A skill lives
in its own folder here, and everything the model sees comes from that folder, so a skill can
be reviewed or changed without touching the Java code.

```
skills/
  <skill_name>/
    SKILL.md      front matter (settings) + the instructions given to the model
    schema.json   the JSON schema the model's answer must follow (strict)
```

## SKILL.md front matter

| Key | Meaning |
|---|---|
| `name` | The skill's name; must match its folder |
| `description` | One line: what the skill decides |
| `version` | Bump when the instructions or schema change |
| `model` | The model the skill calls (default `gpt-6-luna`). The `TRACEASSIST_MODEL` environment variable, when set, overrides it for every skill and for the answer writer |
| `temperature` | Sent when the model accepts it; models that reject it are called without it |
| `reasoning_effort` | Optional: `low`, `medium` or `high` for a reasoning model; models that reject it are called without it |
| `schema` | The schema file (default `schema.json`) |

Everything below the front matter is the model's instructions.

## How a skill is run

The Java side is `AiSkill` (`src/.../views/AiSkill.java`):
1. It loads the skill files from the plug-in.
2. It sends the instructions plus a JSON input to the OpenAI Responses API, with the schema
   as a strict structured-output format.
3. It returns the parsed JSON object.

The skill files are re-read for every call, so an edited skill applies to the next question
without restarting Trace Compass. Decisions are cached per skill text and input, so the same
input gives the same decision for the rest of the session.

The Java code always checks a skill's answer before using it, for example that every TID it
names exists in the trace, and falls back to the previous behaviour when the answer is
unusable or the model cannot be reached.

## Skills

| Skill | Status | Decides |
|---|---|---|
| `thread_finder` | Implemented (its suspects are checked by `ThreadSearch`, code) | For a question with no TID: the scope (thread, process or trace), the symptom, and the target or up to 5 suspects to search |
| `match_judge` | Implemented (called by `ThreadSearch`) | After a search level: whether each suspect's evidence matches the question (match / weak / no), from code-computed comparisons; code turns the verdicts into scores, percentages and a confidence label |
| `view_picker` | Implemented (called by `ViewPicker`) | Which views show the answer's evidence (1 to 3), the evidence moment they show, each view's focus (a thread, a CPU, threads to plot, series to tick) and what to look at in each; it reads the view cards below. Code computes the zoom from the moment and the first view's zoom rule, and checks every choice |

The design is in `thread_finder_design.md` in the research repository.

## View cards

`views/<key>/VIEW.md`, one per view TraceAssist can open and drive (13). Each is the view's
own skill file, read by `view_picker` and by code:

| Front matter | Used by |
|---|---|
| `key`, `name`, `view_id` | code: which Trace Compass view it is (checked against the code's view ids) |
| `tsp_output` | code: the Trace Server output (data provider id) showing the same thing in the VS Code trace viewer, copied into each view of the plan; `none` when the server has no such output (Critical Path, Statistics, Event Density) |
| `focus` | both: what the view can be focused on: `thread`, `cpu`, `plot_threads`, `series` or `none` |
| `zoom_pad`, `zoom_min_span_ms` | code: the zoom rule, the moment plus `zoom_pad` × its length on each side, at least `zoom_min_span_ms` |
| `needs_events` | code: optional event-name prefixes (e.g. `block_rq_`); the card is not offered when the trace has none of them, since the view would be empty |

The body (what it shows, which questions it answers, what can be focused, its zoom rule, its
pitfalls) is what the view picker reads. All views share one time range, so the first view in
a plan sets the zoom. Cards are re-read on every question, like the skills.

