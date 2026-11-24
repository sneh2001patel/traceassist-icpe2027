#!/usr/bin/env bash
#
# Records an LTTng kernel trace of one symptom bench program with one fault.
#
# Usage: ./capture.sh <program> <fault> [-d DURATION] [--without GROUPS] [-- program options]
#   ./capture.sh batch_server holder_sleeps
#   ./capture.sh ticker none -d 60s
#   ./capture.sh jobrunner crash --without signal     # the "the trace can't show it" variant
#
# GROUPS is a comma-separated list of optional event groups to leave out: net, block, signal,
# mem (see symptoms.json "event_groups"). The base group (scheduling, timers and interrupts,
# every syscall, statedump) is always recorded.
#
# Output, in runs/<run id>/ (the run id is "<program>-<4 hex digits>", so the trace's name
# never names the fault):
#   trace/          the LTTng trace: the only thing to give the systems under test
#   ground_truth/   the answer key written by the program (ground_truth.json, series.csv)
#   capture.json    the fault, the event groups recorded and the ones missing
#   program.log     the program's output
# and one line in runs/index.csv. Never give ground_truth/, capture.json, program.log or
# index.csv to the systems under test.
#
# Requires: a root session daemon (sudo lttng-sessiond --daemonize) and the user in the
# "tracing" group.

set -euo pipefail

usage() { sed -n '5,9p' "$0" >&2; exit 2; }
[ $# -ge 2 ] || usage

PROGRAM="$1"
FAULT="$2"
shift 2
DURATION=30s
WITHOUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        -d) DURATION="$2"; shift 2 ;;
        --without) WITHOUT="$2"; shift 2 ;;
        --) shift; break ;;
        *) usage ;;
    esac
done

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${BENCH_DIR}/${PROGRAM}"
make -s -C "${BENCH_DIR}" "${PROGRAM}"
"${BINARY}" --list-faults | python3 -c '
import json, sys
names = [f["name"] for f in json.load(sys.stdin)["faults"]]
if sys.argv[1] not in names:
    sys.exit("unknown fault %r; this program has: %s" % (sys.argv[1], ", ".join(names)))
' "${FAULT}"

if ! lttng list >/dev/null 2>&1; then
    echo "No LTTng session daemon. Start one first: sudo lttng-sessiond --daemonize" >&2
    exit 1
fi

RUN_ID="${PROGRAM}-$(od -An -N2 -tx1 /dev/urandom | tr -d ' \n')"
RUN_DIR="${BENCH_DIR}/runs/${RUN_ID}"
CHANNEL="bench"
mkdir -p "${RUN_DIR}"

excluded() { [[ ",${WITHOUT}," == *",$1,"* ]]; }

AVAILABLE="$(lttng list --kernel 2>/dev/null | grep -oE '`[a-z0-9_]+`' | tr -d '`')"
RECORDED="base"
MISSING=""
UNAVAILABLE=""
enable_group() { # enable_group <group> <event list or pattern>...
    local group="$1"; shift
    if excluded "${group}"; then
        MISSING="${MISSING:+${MISSING},}${group}"
        return
    fi
    local ok=0 events pattern
    for events in "$@"; do
        # Enable only what this kernel has: LTTng accepts a wildcard that matches nothing.
        pattern="^($(echo "${events}" | sed 's/\*/[a-z0-9_]*/g; s/,/|/g'))$"
        if grep -qE "${pattern}" <<<"${AVAILABLE}" &&
            lttng enable-event --kernel --channel="${CHANNEL}" "${events}" >/dev/null 2>&1; then
            ok=1
        fi
    done
    if [ "${ok}" = 1 ]; then
        RECORDED="${RECORDED},${group}"
        echo "  ${group}: on"
    else
        UNAVAILABLE="${UNAVAILABLE:+${UNAVAILABLE},}${group}"
        echo "  ${group}: not available on this kernel"
    fi
}

echo "== LTTng session ${RUN_ID} (${PROGRAM} --fault ${FAULT}, ${DURATION}) =="
lttng create "${RUN_ID}" --output="${RUN_DIR}/trace" >/dev/null
lttng enable-channel --kernel --subbuf-size=8M --num-subbuf=8 "${CHANNEL}" >/dev/null

# Base: the same events as CASCON/Experiment/capture.sh, plus migrations and exec. The
# timer/IRQ events let Trace Compass attribute timer wake-ups to a TIMER edge instead of the
# idle task (see lttng_critical_path_demo/capture.sh).
lttng enable-event --kernel --channel="${CHANNEL}" \
    sched_switch,sched_process_fork,sched_process_exit,sched_process_free,sched_wakeup,sched_wakeup_new,sched_waking,sched_migrate_task,sched_process_exec \
    >/dev/null
lttng enable-event --kernel --channel="${CHANNEL}" \
    timer_hrtimer_start,timer_hrtimer_cancel,timer_hrtimer_expire_entry,timer_hrtimer_expire_exit,irq_handler_entry,irq_handler_exit,irq_softirq_entry,irq_softirq_exit,irq_softirq_raise \
    >/dev/null
lttng enable-event --kernel --channel="${CHANNEL}" \
    x86_irq_vectors_local_timer_entry,x86_irq_vectors_local_timer_exit,x86_irq_vectors_reschedule_entry,x86_irq_vectors_reschedule_exit,x86_irq_vectors_call_function_entry,x86_irq_vectors_call_function_exit,x86_irq_vectors_call_function_single_entry,x86_irq_vectors_call_function_single_exit \
    >/dev/null 2>&1 || echo "  (x86 IRQ vector events unavailable, continuing)"
lttng enable-event --kernel --channel="${CHANNEL}" --syscall --all >/dev/null
lttng enable-event --kernel --channel="${CHANNEL}" \
    lttng_statedump_process_state,lttng_statedump_file_descriptor,lttng_statedump_block_device \
    >/dev/null 2>&1 || echo "  (statedump events unavailable, continuing)"
echo "  base: on"

enable_group net 'net_*' 'netif_*'
enable_group block 'block_*'
enable_group signal signal_generate,signal_deliver
enable_group mem 'kmem_*' 'x86_exceptions_page_fault_*'

# The answer key goes through two pipes opened before tracing starts, so the traced program writes
# to anonymous pipes, not to files whose names give the bench away (bench.h, b_open_key).
mkdir -p "${RUN_DIR}/ground_truth"
exec 8> >(cat > "${RUN_DIR}/ground_truth/series.csv") 9> >(cat > "${RUN_DIR}/ground_truth/ground_truth.json")
export BENCH_KEY_FD=9 BENCH_SERIES_FD=8

lttng start "${RUN_ID}" >/dev/null
echo "== Running ${PROGRAM} --fault ${FAULT} -d ${DURATION} =="
# A stuck run (deadlock, hang, never exits) is ended by the program's watchdog. It first asks,
# through these FIFOs, for tracing to stop, so the trace ends with the threads still blocked
# rather than showing the watchdog waking them all (see bench.h, b_stop_tracing_first).
STOP_REQ="${RUN_DIR}/.trace_stop_request"
STOP_ACK="${RUN_DIR}/.trace_stopped"
mkfifo "${STOP_REQ}" "${STOP_ACK}"
( if read -r -n 1 _ < "${STOP_REQ}"; then
      lttng stop "${RUN_ID}" >/dev/null 2>&1
      echo stopped > "${STOP_ACK}"
  fi ) &
STOP_HELPER=$!
export BENCH_TRACE_STOP_FIFO="${STOP_REQ}" BENCH_TRACE_STOPPED_FIFO="${STOP_ACK}"

set +e
"${BINARY}" --fault "${FAULT}" -d "${DURATION}" -o "${RUN_DIR}/ground_truth" \
    --data "${RUN_DIR}/data" "$@" > "${RUN_DIR}/program.log" 2>&1
STATUS=$?
set -e
exec 8>&- 9>&-
unset BENCH_KEY_FD BENCH_SERIES_FD
sleep 0.5   # let the two cat processes finish writing the answer key
[ -s "${RUN_DIR}/ground_truth/series.csv" ] && [ "$(wc -l < "${RUN_DIR}/ground_truth/series.csv")" -gt 1 ] \
    || rm -f "${RUN_DIR}/ground_truth/series.csv"
lttng stop "${RUN_ID}" >/dev/null 2>&1 || true   # already stopped if the watchdog asked
kill "${STOP_HELPER}" 2>/dev/null || true
wait "${STOP_HELPER}" 2>/dev/null || true
rm -f "${STOP_REQ}" "${STOP_ACK}"
unset BENCH_TRACE_STOP_FIFO BENCH_TRACE_STOPPED_FIFO
lttng destroy "${RUN_ID}" >/dev/null
rm -rf "${RUN_DIR}/data"

python3 - "${RUN_DIR}" "${PROGRAM}" "${FAULT}" "${DURATION}" "${RECORDED}" "${MISSING}" \
    "${UNAVAILABLE}" "${STATUS}" <<'EOF'
import json, sys, datetime
run_dir, program, fault, duration, recorded, missing, unavailable, status = sys.argv[1:]
split = lambda s: [x for x in s.split(",") if x]
info = {
    "run_id": run_dir.rstrip("/").split("/")[-1],
    "program": program,
    "fault": fault,
    "duration": duration,
    "events_recorded": split(recorded),
    "events_left_out": split(missing),
    "events_unavailable": split(unavailable),
    "program_exit_status": int(status),
    "recorded_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
}
open(f"{run_dir}/capture.json", "w").write(json.dumps(info, indent=2) + "\n")
index = f"{run_dir}/../index.csv"
import os
new = not os.path.exists(index)
with open(index, "a") as f:
    if new:
        f.write("run_id,program,fault,duration,events_left_out,events_unavailable,recorded_at\n")
    f.write(",".join([info["run_id"], program, fault, duration, "+".join(split(missing)),
                      "+".join(split(unavailable)), info["recorded_at"]]) + "\n")
EOF

echo "== Done (program exit status ${STATUS}) =="
echo "Trace:      ${RUN_DIR}/trace"
echo "Answer key: ${RUN_DIR}/ground_truth"
du -sh "${RUN_DIR}/trace" | cut -f1 | sed 's/^/Trace size: /'
