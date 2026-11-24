"""Offline regression checks for evidence fidelity and the experiment workflow."""
from contextlib import redirect_stdout
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collect_tmll as collector
import tmll_baseline as baseline


class EvidenceTests(unittest.TestCase):
    def test_questions_identical_to_both_baselines(self):
        actual = baseline.load_questions()
        self.assertEqual(len(actual), 13)
        for directory in ("llm_baseline", "RAG_baseline"):
            expected = json.loads((baseline.HERE.parent / directory / "questions.json").read_text())
            self.assertEqual(actual, expected)

    def test_native_serialization_preserves_nanosecond_timestamps_and_indices(self):
        import pandas as pd
        timestamp = 1791918390123456789
        frame = pd.DataFrame({"start_time": [timestamp], "y": [float("nan")]},
                             index=pd.to_datetime([timestamp]))
        result = collector.json_value(frame)
        self.assertEqual(result["rows"][0][0], timestamp)
        self.assertIsNone(result["rows"][0][1])
        self.assertIn("123456789", result["index"][0])
        json.dumps(result, allow_nan=False)

    def test_sampling_keeps_every_thread_and_marks_omissions(self):
        rows = [[tid, n] for tid in (101, 202) for n in range(20)]
        value = {"kind": "dataframe", "columns": ["entry_id", "start_time"],
                 "rows": rows, "index": list(range(40))}
        result = baseline.summarize(value, 2)
        self.assertEqual(result["rows"], [[101, 0], [101, 19], [202, 0], [202, 19]])
        self.assertEqual(result["omitted_rows"], 36)
        self.assertEqual(result["index"], [0, 19, 20, 39])

    def test_statistics_and_anomaly_counts_use_unsampled_data(self):
        value = {"kind": "dataframe", "columns": ["y", "cpu_is_anomaly"],
                 "rows": [[1, False], [100, True], [2, False]], "index": [10, 20, 30]}
        result = baseline.summarize(value, 2)
        self.assertEqual(result["all_returned_samples_y_statistics"]["max"], 100)
        self.assertEqual(result["anomaly_rows_total"], 1)
        self.assertEqual(result["anomaly_examples"][0]["index"], 20)

    def test_evidence_budget_is_enforced_without_truncating_json(self):
        import tiktoken
        encoding = tiktoken.get_encoding("o200k_base")
        value = {"series": {"kind": "dataframe", "columns": ["x", "y"],
                            "rows": [[i, i] for i in range(100)], "index": list(range(100))}}
        text, tokens, rows = baseline.build_evidence(value, encoding, 500, 100)
        self.assertLessEqual(tokens, 500)
        self.assertLess(rows, 100)
        self.assertIn("presentation", json.loads(text.split("\n", 1)[1]))
        with self.assertRaisesRegex(ValueError, "metadata alone"):
            baseline.build_evidence({"metadata": "too much " * 1000}, encoding, 10, 1)

    def test_noncompleted_server_results_are_errors(self):
        response = SimpleNamespace(status_code=200, model=SimpleNamespace(
            status=SimpleNamespace(name="RUNNING"), model={"partial": True}))
        with self.assertRaisesRegex(RuntimeError, "not COMPLETED"):
            collector.checked_model(response)

    def test_large_inventory_fits_budget_and_retains_workload(self):
        import tiktoken
        nodes = [{"id": i, "parent_id": -1, "name": f"unrelated-thread-{i}"} for i in range(1000)]
        nodes[503]["name"] = "worker-2"
        nodes[503]["parent_id"] = 502
        frame = {"kind": "dataframe", "columns": ["entry_id", "start_time"],
                 "rows": [[i, 1791918390123456789] for i in range(1000)], "index": list(range(1000))}
        raw = {"outputs": [{"descriptor": {"name": "Thread Status"}, "tree": {"nodes": nodes},
                            "data": frame}]}
        text, tokens, _ = baseline.build_evidence(raw, tiktoken.get_encoding("o200k_base"), 10000, 100)
        self.assertLessEqual(tokens, 10000)
        output = json.loads(text.split("\n", 1)[1])["outputs"][0]
        kept = {node["id"] for node in output["tree"]["nodes"]}
        self.assertTrue({502, 503}.issubset(kept))
        self.assertTrue(any(row[0] == 503 for row in output["data"]["rows"]))
        self.assertGreater(output["inventory_sampling"]["tree_nodes_omitted"], 0)
        self.assertEqual(len(raw["outputs"][0]["tree"]["nodes"]), 1000)
        self.assertEqual(len(raw["outputs"][0]["data"]["rows"]), 1000)

    def test_xy_inventory_selection_retains_named_workload_series(self):
        names = [f"system-thread-{i}" for i in range(100)] + ["trace->worker-2", "trace->flusher"]
        frame = {"kind": "dataframe", "columns": ["x", "y"], "rows": [[1, 2]], "index": [0]}
        output = {"data": {name: frame for name in names}}
        result = baseline.compact_output(output, 10)
        self.assertEqual(len(result["data"]), 10)
        self.assertIn("trace->worker-2", result["data"])
        self.assertIn("trace->flusher", result["data"])
        self.assertEqual(result["inventory_sampling"]["xy_series_omitted"], 92)

    def test_workload_tids_and_cpus_survive_entity_sampling(self):
        threads = baseline.workload_threads(["worker-2 159975 159971 159971", "dconf worker 53340 53292 1",
                                             "kworker/3:0H 41 41 2", "batch_server 159971 159971 1"])
        self.assertEqual(threads, {"159975": "worker-2", "159971": "batch_server"})
        tids = frozenset(threads)
        names = [str(i) for i in range(100)] + ["159975", "CPU 3 Threads", "CPU 3 States"]
        kept = baseline.select_entities(names, 5, str, tids)
        self.assertTrue({"159975", "CPU 3 Threads", "CPU 3 States"}.issubset(kept))
        self.assertTrue(baseline.mentions_workload("thread 159975", tids))
        self.assertFalse(baseline.mentions_workload("kworker/u64:0", tids))

    def test_state_totals_use_every_state_once_and_label_cpu_rows(self):
        nodes = [{"id": 1, "name": "worker-2 159975 159971 159971"}, {"id": 2, "name": "CPU 3 Threads"},
                 {"id": 3, "name": "other 7 7 1"}]
        blocked, cpu = {"parentKey": "Wait blocked"}, {"parentKey": "Usermode"}
        rows = [[1, 0, 25_000_000, None, blocked, None], [1, 0, 25_000_000, None, blocked, None],
                [1, 30_000_000, 80_000_000, None, blocked, None],
                [2, 0, 1_000_000, "worker-2 (159975)", cpu, None], [3, 0, 9, None, cpu, None]]
        output = {"tree": {"nodes": nodes}, "workload_sampling": {"resample_freq": "100us"},
                  "workload_data": {"kind": "dataframe", "index": list(range(5)), "rows": rows,
                                    "columns": ["entry_id", "start_time", "end_time", "label", "style", "value"]}}
        totals = baseline.state_totals(output, frozenset({"159975"}))
        self.assertEqual(totals["resample_freq"], "100us")
        by_entry = {(r["entry"], r["state"]): r for r in totals["rows"]}
        self.assertEqual(set(by_entry), {("worker-2 159975 159971 159971", "Wait blocked"),
                                         ("CPU 3 Threads", "Usermode")})
        blocked_row = by_entry[("worker-2 159975 159971 159971", "Wait blocked")]
        self.assertEqual(blocked_row["count"], 2)
        self.assertEqual(blocked_row["total_ms"], 75.0)
        self.assertEqual(blocked_row["duration_histogram_ms"], {"25-30": 1, "50-60": 1})
        presented = baseline.compact_output(output, 10, frozenset({"159975"}))
        self.assertNotIn("workload_data", presented)
        self.assertIn("workload_state_totals", presented)

    def test_other_entries_get_fewer_example_rows(self):
        rows = [[entry, n] for entry in (1, 2) for n in range(10)]
        value = {"kind": "dataframe", "columns": ["entry_id", "start_time"], "rows": rows,
                 "index": list(range(20))}
        result = baseline.summarize(value, 5, 2, {1})
        self.assertEqual(sum(row[0] == 1 for row in result["rows"]), 5)
        self.assertEqual(sum(row[0] == 2 for row in result["rows"]), 2)
        frame = {"kind": "dataframe", "columns": ["x", "y"], "rows": [[i, i] for i in range(10)],
                 "index": list(range(10))}
        series = baseline.summarize({"trace->worker-2 1": frame, "trace->sshd 2": frame}, 5, 2, set())
        self.assertEqual(series["trace->worker-2 1"]["shown_rows"], 5)
        self.assertEqual(series["trace->sshd 2"]["shown_rows"], 2)

    def test_collection_bounds_native_tree_and_retains_ancestors(self):
        class Tree:
            def __init__(self, nodes):
                self.nodes = nodes
        nodes = [SimpleNamespace(id=i, parent_id=-1, name=f"thread-{i}") for i in range(1000)]
        nodes[503].name = "worker-2"
        nodes[503].parent_id = 502
        original = Tree(nodes)
        bounded = collector.bound_tree(original, 20)
        self.assertLessEqual(len(bounded.nodes), 21)
        self.assertTrue({502, 503}.issubset({n.id for n in bounded.nodes}))
        self.assertEqual(len(original.nodes), 1000)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.evidence = root / "evidence"
        self.results = root / "results"
        self.patchers = [patch.object(baseline, "EVIDENCE_DIR", self.evidence),
                         patch.object(baseline, "RESULTS_DIR", self.results),
                         patch.object(baseline, "ANSWERS_JSONL", self.results / "answers.jsonl")]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.write_evidence("TMLL ANALYSIS RESULTS\n{}")
        self.args = SimpleNamespace(traces=None, questions=None, model="test-model", repeats=1,
                                    reasoning_effort=None, max_output_tokens=100, dry_run=False,
                                    max_retries=0, timeout=5, workers=2)
        self.calls = []

        def create(**kwargs):
            self.calls.append(kwargs)
            return SimpleNamespace(output_text="An answer based on the TMLL results.", status="completed",
                                   model="test-model", incomplete_details=None,
                                   usage=SimpleNamespace(input_tokens=40, output_tokens=10,
                                       input_tokens_details=SimpleNamespace(cached_tokens=0),
                                       output_tokens_details=SimpleNamespace(reasoning_tokens=0)))

        self.create = create
        client = SimpleNamespace(responses=SimpleNamespace(create=create))
        patcher = patch("openai.OpenAI", return_value=client)
        self.openai = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = redirect_stdout(io.StringIO())
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)

    def write_evidence(self, text):
        directory = self.evidence / "2m"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "tmll.txt").write_text(text)
        (directory / "tmll.json").write_text(json.dumps({
            "trace": "2m", "run": "fixture", "tokens": 20, "tmll_revision": "fixture-revision",
            "evidence_sha256": baseline.digest(text)}))

    def test_all_questions_isolated_resume_and_export(self):
        baseline.cmd_run(self.args)
        self.assertEqual(len(self.calls), 13)
        expected_questions = {q["question"] for q in baseline.load_questions()}
        seen = set()
        for call in self.calls:
            self.assertFalse(call["store"])
            self.assertEqual(len(call["input"]), 1)
            content = call["input"][0]["content"]
            self.assertEqual(len(content), 2)
            self.assertEqual(content[0]["text"], "TMLL ANALYSIS RESULTS\n{}")
            seen.add(content[1]["text"].split("Question: ", 1)[1])
        self.assertEqual(seen, expected_questions)
        baseline.cmd_run(self.args)
        self.assertEqual(len(self.calls), 13)
        baseline.cmd_export(SimpleNamespace(repeat=1))
        with (self.results / "answers_repeat1.csv").open() as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 13)
        self.assertEqual(rows[-1]["question_id"], "Q13")
        self.assertIn("## Q13", (self.results / "answers_repeat1.md").read_text())

    def test_failures_incomplete_and_empty_answers_are_retried(self):
        self.args.questions = ["Q1"]
        baseline.cmd_run(self.args)
        original = list(baseline.records())[0]
        for change in ({"error": "failure"}, {"status": "incomplete"}, {"answer": " "}):
            baseline.ANSWERS_JSONL.write_text(json.dumps({**original, **change}) + "\n")
            before = len(self.calls)
            baseline.cmd_run(self.args)
            self.assertEqual(len(self.calls), before + 1)

    def test_evidence_and_settings_changes_do_not_reuse_old_answers(self):
        self.args.questions = ["Q1"]
        baseline.cmd_run(self.args)
        self.write_evidence("TMLL ANALYSIS RESULTS\n{\"updated\": true}")
        baseline.cmd_run(self.args)
        self.args.reasoning_effort = "low"
        baseline.cmd_run(self.args)
        self.assertEqual(len(self.calls), 3)

    def test_dry_run_does_not_construct_api_client_or_write_answers(self):
        self.args.dry_run = True
        baseline.cmd_run(self.args)
        self.openai.assert_not_called()
        self.assertFalse(baseline.ANSWERS_JSONL.exists())

    def test_invalid_selections_and_tampered_evidence_fail(self):
        with self.assertRaisesRegex(ValueError, "Unknown question"):
            baseline.load_questions(["Q14"])
        with self.assertRaisesRegex(ValueError, "Missing prepared"):
            baseline.load_evidence(["30m"])
        (self.evidence / "2m/tmll.txt").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            baseline.load_evidence()


if __name__ == "__main__":
    unittest.main()
