/*
 * ticker: a sampler thread that must run every 2 ms (sleep to an absolute deadline, then
 * 0.2 ms of CPU work), plus an uploader that wakes every 500 ms for 1 ms of work. The
 * periodic_delay_demo workload (lttng_critical_path_demo/), rebuilt with a fault switch for
 * the timing symptoms. All threads are pinned to one CPU (--cpu).
 *
 * The sampler records, for every cycle, how late it woke (lateness_ms) and its work time
 * (cycle_ms). If a cycle overruns the next deadline, the sampler skips ahead instead of
 * running back-to-back to catch up, and counts the overrun.
 *
 * Build: make ticker        Run: ./ticker --fault one_off_delay -d 30s -o gt/
 */
#include "bench.h"

#define PERIOD_MS 2.0
#define WORK_MS 0.2

static const bench_fault faults[] = {
    { "one_off_delay",
      "once, at 50% of the run, the maintenance thread (SCHED_FIFO 10, same CPU) spins for "
      "30 ms; the sampler wakes ~30 ms late once",
      "one_off_delay,scheduling_delay", "cpu_starvation,long_blocked_waits" },
    { "jitter",
      "all run long, the maintenance thread (SCHED_FIFO 10, same CPU) spins 0.3-1.8 ms at "
      "random every 0.5-2.5 ms; the sampler's wake-up lateness varies from 0 to ~1.8 ms",
      "jitter,scheduling_delay", "tail_latency" },
    { "gradual_slowdown",
      "the sampler's work per cycle grows steadily from 0.1 ms to 3 ms over the run, so its "
      "cycles stretch and, past ~65% of the run, overrun the 2 ms period",
      "gradual_slowdown", "cpu_hog,jitter" },
    { "sudden_change",
      "at 50% of the run the sampler's work per cycle jumps from 0.2 ms to 2.5 ms, so every "
      "later cycle overruns the 2 ms period",
      "sudden_change", "cpu_hog" },
    { "oversleeping",
      "the sampler's timer slack is 4 ms (prctl PR_SET_TIMERSLACK), so its 2 ms-period sleeps "
      "end up to 4 ms late",
      "oversleeping", "jitter,tail_latency" },
    { "rt_preempted",
      "the sampler runs at SCHED_FIFO 20; every 300 ms the maintenance thread (SCHED_FIFO 50, "
      "same CPU) spins for 5 ms and preempts it",
      "rt_preempted,scheduling_delay", "jitter,tail_latency,one_off_delay" },
};
static const bench_program program = {
    "ticker",
    "a sampler thread runs every 2 ms (0.2 ms of work per cycle) and an uploader thread wakes "
    "every 500 ms",
    faults, sizeof faults / sizeof faults[0],
};

#define MAX_CYCLES 2000000
static double *lateness;
static int cycles, overruns;
static double work_first_half, work_second_half;
static int n_first, n_second;

static void record_metrics(void) {
    int n = cycles < MAX_CYCLES ? cycles : MAX_CYCLES;
    b_metric("cycles", cycles);
    b_metric("overruns", overruns);
    b_metric("lateness_ms_mean", b_mean(lateness, n));
    b_metric("lateness_ms_p50", b_quantile(lateness, n, 0.5));
    b_metric("lateness_ms_p99", b_quantile(lateness, n, 0.99));
    b_metric("lateness_ms_max", b_quantile(lateness, n, 1.0));
    b_metric("cycle_ms_mean_first_half", n_first ? work_first_half / n_first : 0);
    b_metric("cycle_ms_mean_second_half", n_second ? work_second_half / n_second : 0);
}

static double work_ms(int64_t now) {
    double progress = b_rel(now) / B.duration_s;
    if (b_fault_is("gradual_slowdown")) return 0.1 + 2.9 * progress;
    if (b_fault_is("sudden_change")) return progress < 0.5 ? WORK_MS : 2.5;
    return WORK_MS;
}

static void *sampler_main(void *arg) {
    (void)arg;
    b_thread_start("sampler", "periodic: must run every 2 ms");
    b_pin(B.cpu);
    if (b_fault_is("rt_preempted")) b_fifo(20);
    if (b_fault_is("oversleeping")) prctl(PR_SET_TIMERSLACK, 4000000UL, 0, 0, 0);
    int64_t period = (int64_t)(PERIOD_MS * 1e6);
    int64_t next = b_mono() + period;
    while (b_running()) {
        b_sleep_until(next);
        int64_t woke = b_mono();
        double late = (double)(woke - next) / 1e6;
        b_burn_ms(work_ms(woke));
        int64_t done = b_mono();
        double cycle = (double)(done - woke) / 1e6;
        if (cycles < MAX_CYCLES) lateness[cycles] = late;
        cycles++;
        if (b_rel(woke) < B.duration_s / 2) { work_first_half += cycle; n_first++; }
        else { work_second_half += cycle; n_second++; }
        b_series("lateness_ms", next, late);
        b_series("cycle_ms", woke, cycle);
        if (late >= 1.0) b_interval("late_wakeup", next, woke, "woke %.2f ms late", late);
        next += period;
        if (done > next) { /* overran the next deadline: skip ahead */
            overruns++;
            while (next < done) next += period;
        }
    }
    return NULL;
}

static void *uploader_main(void *arg) {
    (void)arg;
    b_thread_start("uploader", "wakes every 500 ms for 1 ms of work");
    b_pin(B.cpu);
    while (b_running()) {
        b_sleep_ms(500);
        b_burn_ms(1);
    }
    return NULL;
}

static void *maintenance_main(void *arg) {
    (void)arg;
    b_thread_start("maintenance", "background maintenance");
    b_pin(B.cpu);
    if (b_fault_is("one_off_delay")) {
        b_fifo(10);
        b_sleep_until(b_at(0.5));
        int64_t t0 = b_mono();
        b_spin_ms(30);
        b_interval("cpu_burst", t0, b_mono(), "spins 30 ms at SCHED_FIFO 10 on the sampler's CPU");
    } else if (b_fault_is("jitter")) {
        b_fifo(10);
        int64_t t0 = b_mono();
        while (b_running()) {
            b_sleep_ms(0.5 + 2.0 * rand() / RAND_MAX);
            b_spin_ms(0.3 + 1.5 * rand() / RAND_MAX);
        }
        b_interval("cpu_bursts", t0, b_mono(),
                   "spins 0.3-1.8 ms every 0.5-2.5 ms at SCHED_FIFO 10 on the sampler's CPU");
    } else if (b_fault_is("rt_preempted")) {
        b_fifo(50);
        while (b_running()) {
            b_sleep_ms(300);
            int64_t t0 = b_mono();
            b_spin_ms(5);
            b_interval("cpu_burst", t0, b_mono(), "spins 5 ms at SCHED_FIFO 50, preempting the "
                       "sampler (SCHED_FIFO 20)");
        }
    } else {
        while (b_running()) b_sleep_ms(1000); /* idle: wakes once a second */
    }
    return NULL;
}

int main(int argc, char **argv) {
    b_init(argc, argv, &program, 3);
    b_pin(B.cpu);
    lateness = calloc(MAX_CYCLES, sizeof *lateness);
    b_before_finish = record_metrics;
    pthread_t s = b_spawn(sampler_main, NULL);
    pthread_t u = b_spawn(uploader_main, NULL);
    pthread_t m = b_spawn(maintenance_main, NULL);
    pthread_join(s, NULL);
    pthread_join(u, NULL);
    pthread_join(m, NULL);
    printf("[ticker] %d cycles, %d overruns\n", cycles, overruns);
    b_finish();
    return 0;
}
