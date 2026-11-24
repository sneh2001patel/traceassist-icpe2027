#!/usr/bin/env python3
"""Collect structured TMLL results. Invoked in a timeout-bounded subprocess."""
import argparse
from dataclasses import asdict, is_dataclass
from enum import Enum
import gzip
import json
import math
from pathlib import Path
import subprocess
import sys


def bound_tree(tree, limit, tids=frozenset()):
    from tmll_baseline import select_entities
    return with_ancestors(tree, select_entities(tree.nodes, limit, lambda n: n.name, tids))


def with_ancestors(tree, chosen):
    nodes = tree.nodes
    by_id = {node.id: node for node in nodes}
    ids = {node.id for node in chosen}
    for node in chosen:
        parent, visited = node.parent_id, set()
        while parent in by_id and parent not in visited:
            visited.add(parent)
            ids.add(parent)
            parent = by_id[parent].parent_id
    return type(tree)([node for node in nodes if node.id in ids])


def json_value(value):
    """Preserve integer timestamps, dataframe indices, and structured styles."""
    import numpy as np
    import pandas as pd

    if isinstance(value, pd.DataFrame):
        return {"kind": "dataframe", "columns": list(map(str, value.columns)),
                "index_name": value.index.name,
                "index": json_value(value.index.tolist()),
                "rows": [json_value(list(row)) for row in value.itertuples(index=False, name=None)]}
    if is_dataclass(value):
        return json_value(asdict(value))
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, dict):
        return {str(k): json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(v) for v in value]
    if isinstance(value, np.generic):
        return json_value(value.item())
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (pd.Timestamp, pd.Timedelta)):
        return str(value)
    if hasattr(value, "__dict__"):
        return json_value(vars(value))
    return str(value)


def checked_model(response):
    if response.status_code != 200 or response.model is None:
        raise RuntimeError(f"TSP request failed: HTTP {response.status_code}")
    if getattr(response.model, "status", None) is not None:
        if response.model.status.name != "COMPLETED":
            raise RuntimeError(f"TSP result is {response.model.status.name}, not COMPLETED")
    model = getattr(response.model, "model", None)
    if model is None:
        raise RuntimeError("TSP returned no result model")
    return model


def collect(args):
    source = Path(args.tmll_source).resolve()
    if not (source / "tmll/tsp/tsp/tsp_client.py").is_file():
        raise RuntimeError("TMLL TSP submodule missing. Run: "
                           f"git -C {source} submodule update --init tmll/tsp")
    # The bundled TSP client uses both tmll.tsp.tsp and absolute tsp imports.
    sys.path[:0] = [str(source), str(source / "tmll/tsp")]
    from tmll.tmll_client import TMLLClient

    client = TMLLClient(args.host, args.port, install_tsp_server=False, verbose=False)
    if client.health_status != 200:
        raise RuntimeError(f"Trace Server unavailable at {args.host}:{args.port}; start it first")
    experiment = client.create_experiment(
        traces=[{"path": str(Path(args.kernel).resolve()), "name": f"bench-{args.label}-kernel"}],
        experiment_name=f"bench-tmll-baseline-{args.run}")
    if experiment is None:
        raise RuntimeError("TMLL could not import the kernel trace")
    import pandas as pd
    requested_ns = pd.Timedelta(args.resample_freq).value
    if requested_ns <= 0:
        raise ValueError("--resample-freq must be a positive duration")
    # Bound the number of samples per series so longer traces do not multiply
    # memory use. The full time range is still analyzed; record the actual rate.
    minimum_ns = math.ceil((experiment.end - experiment.start) / args.max_samples)
    effective_freq = f"{max(requested_ns, minimum_ns)}ns"
    print(f"  sampling full trace at {effective_freq} (requested {args.resample_freq}, "
          f"at most ~{args.max_samples} points per series)", flush=True)
    revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
    result = {
        "trace": args.label, "run": args.run, "program": args.program, "tmll_revision": revision,
        "experiment_id": experiment.uuid,
        "trace_begin_ns": experiment.start, "trace_end_ns": experiment.end,
        "trace_events": experiment.num_events,
        "coverage": "Full trace requested; XY and time-graph results are sampled by TMLL.",
        "resample_freq": effective_freq,
        "requested_resample_freq": args.resample_freq,
        "max_samples_per_series": args.max_samples,
        "collection_entity_limit": args.max_entities,
        "workload_resample_freq": args.workload_resample_freq,
        "limitations": [
            "XY and time-graph outputs are sampled at resample_freq; states shorter than the step may be missing.",
            f"Workload thread entries ({args.program}, its threads and child processes, by name or TID) are also fetched "
            "at workload_resample_freq; their states are summarised in workload_state_totals.",
            "Missing outputs and analysis failures are not evidence that a behavior is absent.",
        ],
        "available_outputs": [json_value(o) for o in experiment.outputs],
        "outputs": [], "analyses": {},
    }
    # TMLL otherwise requests every system thread at once, which can exhaust
    # memory on long traces before prompt sampling gets a chance to run.
    native_fetch = client.fetch_data
    sampling = {}
    import tmll_baseline
    from tmll_baseline import is_workload, workload_threads
    tmll_baseline.set_focus(args.program)

    # Workload TIDs name entries in some outputs (e.g. futex waiters), so find them first.
    tids = frozenset()
    status = [o for o in experiment.outputs if o.name == "Thread Status"]
    if status:
        trees = client.fetch_outputs_with_tree(experiment, [status[0].id])
        if trees:
            result["workload_threads"] = workload_threads(n.name for n in trees[0]["tree"].nodes)
            tids = frozenset(result["workload_threads"])
            # From here on the program's threads count as workload by name too (calc-0, client-1).
            tmll_baseline.set_focus(args.program, result["workload_threads"].values())
    print(f"  workload threads: {result.get('workload_threads', {})}", flush=True)

    def bounded_fetch(experiment, outputs, custom_output_ids=None, **kwargs):
        bounded = []
        for item in outputs:
            tree = bound_tree(item["tree"], args.max_entities, tids)
            sampling[item["output"].id] = {
                "resample_freq": kwargs.get("resample_freq"),
                "available_tree_nodes": len(item["tree"].nodes),
                "requested_tree_nodes": len(tree.nodes),
                "omitted_tree_nodes": len(item["tree"].nodes) - len(tree.nodes),
                "policy": "Keep workload threads (by name or TID) and CPUs, evenly sample other "
                          "entries, retain ancestors. Unrequested series/states were not collected; "
                          "their absence is not evidence of inactivity."}
            bounded.append({**item, "tree": tree})
        return native_fetch(experiment, bounded, custom_output_ids=custom_output_ids, **kwargs)

    def workload_fetch(output, tree):
        """Fetch only workload entries at a fine resolution, one TSP request per chunk, so short
        running/runnable states are not skipped. Returns None if there are none."""
        chosen = [n for n in tree.nodes if is_workload(n.name, tids)]
        if not chosen or not args.workload_resample_freq:
            return None
        subtree = with_ancestors(tree, chosen)
        frames = []
        for start, end, _ in client._calculate_intervals(experiment.start, experiment.end,
                                                          args.workload_resample_freq):
            data = native_fetch(experiment, [{"output": output, "tree": subtree}],
                                start=start, end=end, resample_freq=args.workload_resample_freq)
            if data and output.id in data and not data[output.id].empty:
                frames.append(data[output.id])
        workload_sampling = {"resample_freq": args.workload_resample_freq,
                             "requested_tree_nodes": len(subtree.nodes),
                             "workload_entries": [n.name for n in chosen]}
        return (pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()), workload_sampling

    client.fetch_data = bounded_fetch
    selected = experiment.find_outputs(keyword=args.keywords, match_any=True)
    successful = 0
    for output in selected:
        entry = {"descriptor": json_value(output)}
        result["outputs"].append(entry)
        if output.type not in {"TREE_TIME_XY", "TIME_GRAPH", "DATA_TREE"}:
            entry["skipped"] = "Unsupported output type; raw event TABLE outputs are not used."
            continue
        print(f"  collecting {output.name} ({output.type})", flush=True)
        try:
            trees = client.fetch_outputs_with_tree(experiment, [output.id])
            if not trees:
                raise RuntimeError("TMLL returned no output tree")
            entry["tree"] = json_value(trees[0]["tree"])
            if output.type == "DATA_TREE":
                # TMLL's NodeTree joins labels and loses column headers. Preserve the
                # native result through its TSP client for statistics and durations.
                entry["data"] = json_value(checked_model(client.tsp_client.fetch_datatree(
                    exp_uuid=experiment.uuid, output_id=output.id)))
            else:
                data = client.fetch_data(experiment, trees, resample_freq=effective_freq)
                if not data or output.id not in data:
                    raise RuntimeError("TMLL returned no dataset")
                entry["data"] = json_value(data[output.id])
                entry["collection_sampling"] = sampling[output.id]
                if output.type == "TIME_GRAPH":
                    try:
                        fine = workload_fetch(output, trees[0]["tree"])
                        if fine is not None:
                            entry["workload_data"], entry["workload_sampling"] = json_value(fine[0]), fine[1]
                    except Exception as exc:
                        entry["workload_data_error"] = f"{type(exc).__name__}: {exc}"
                    try:
                        # The server samples arrows at nbTimes points, like states; use the
                        # same resolution as the data instead of 2 points for the whole trace.
                        workload_ids = {n.id for n in trees[0]["tree"].nodes if is_workload(n.name, tids)}
                        arrows = []
                        for start, end, count in client._calculate_intervals(
                                experiment.start, experiment.end, effective_freq):
                            arrows += checked_model(client.tsp_client.fetch_timegraph_arrows(
                                exp_uuid=experiment.uuid, output_id=output.id,
                                parameters={"parameters": {"requested_timerange": {
                                    "start": start, "end": end, "nbTimes": count}}})) or []
                        entry["arrows_total"] = len(arrows)
                        entry["arrows"] = json_value([
                            a for a in arrows if getattr(a, "source_id", None) in workload_ids
                            or getattr(a, "target_id", None) in workload_ids])
                        entry["arrows_filter"] = "Only arrows to or from workload entries are kept."
                    except Exception as exc:
                        entry["arrows_error"] = f"{type(exc).__name__}: {exc}"
            successful += 1
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"

    xy_outputs = [o for o in selected if o.type == "TREE_TIME_XY"]
    for name in args.analyses:
        print(f"  running TMLL {name}", flush=True)
        try:
            if not xy_outputs:
                raise RuntimeError("No selected XY outputs available")
            if name == "anomaly":
                from tmll.ml.modules.anomaly_detection.anomaly_detection_module import AnomalyDetection
                module = AnomalyDetection(client, experiment, xy_outputs,
                                          resample_freq=effective_freq)
                analysis = module.find_anomalies(method="zscore")
            else:
                from tmll.ml.modules.root_cause.correlation_module import CorrelationAnalysis
                module = CorrelationAnalysis(client, experiment, xy_outputs,
                                             resample_freq=effective_freq)
                analysis = module.analyze_correlations(method="pearson")
            if analysis is None:
                raise RuntimeError("TMLL returned no analysis result")
            result["analyses"][name] = json_value(analysis)
            result["analyses"][name]["collection_sampling"] = {
                o.id: sampling[o.id] for o in xy_outputs if o.id in sampling}
        except Exception as exc:
            result["analyses"][name] = {"error": f"{type(exc).__name__}: {exc}"}
    if not successful:
        raise RuntimeError("No usable TMLL outputs; check Trace Server analyses and --keywords")
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".tmp")
    with gzip.open(temporary, "wt", encoding="utf-8") as handle:
        json.dump(result, handle, allow_nan=False)
    temporary.replace(destination)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("tmll-source", "kernel", "label", "run", "program", "output"):
        p.add_argument(f"--{name}", required=True)
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--resample-freq", default="10ms")
    p.add_argument("--max-samples", type=int, default=12000)
    p.add_argument("--max-entities", type=int, default=200)
    p.add_argument("--workload-resample-freq", default="100us")
    p.add_argument("--keywords", nargs="+")
    p.add_argument("--analyses", nargs="*", choices=["anomaly", "correlation"],
                   default=["anomaly", "correlation"])
    args = p.parse_args()
    if args.max_samples <= 0 or args.max_entities <= 0:
        p.error("--max-samples and --max-entities must be positive")
    try:
        collect(args)
    except Exception as exc:
        sys.exit(f"TMLL collection failed: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
