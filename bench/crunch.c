/*
 * crunch: every 100 ms, a coordinator gives 8 calc threads 10 ms of CPU work each and waits
 * for all of them (a barrier). Each calc thread is pinned to its own CPU (--cpu .. --cpu+7).
 * The mpi_imbalance_demo / omp_barrier_demo workloads (lttng_critical_path_demo/), rebuilt
 * with a fault switch for the CPU symptoms.
 *
 * Each calc thread records when it finished, relative to the round's start (finish_ms); the
 * coordinator records each round's length (round_ms). A round that overruns its 100 ms slot
 * makes the coordinator skip to the next free slot.
 *
 * Build: make crunch        Run: ./crunch --fault load_imbalance -d 30s -o gt/
 */
#include "bench.h"
#include <semaphore.h>

#define MAX_WORKERS 32
#define TICK_MS 100.0
#define WORK_MS 10.0

static const bench_fault faults[] = {
    { "load_imbalance",
      "calc-0 gets 4x the work (40 ms per round) and the other seven get 10 ms, every round; "
      "the others finish early and wait at the barrier for calc-0",
      "load_imbalance,bottleneck_thread,thread_differences",
      "barrier_straggler,idle_workers,long_blocked_waits" },
    { "barrier_straggler",
      "every calc thread gets the same 10 ms of work, but a monitor thread (SCHED_FIFO 10) on "
      "calc-5's CPU spins 20 ms at the start of every round, so calc-5 is runnable but waiting "
      "and finishes last; everyone waits for it at the barrier",
      "barrier_straggler,scheduling_delay,bottleneck_thread",
      "cpu_starvation,thread_differences,rt_preempted,long_blocked_waits" },
    { "cpu_hog",
      "an indexer thread uses 100% of one CPU (its own) for the whole run",
      "cpu_hog", "thread_differences" },
    { "busy_wait",
      "a collector thread spin-waits on a flag (no syscalls) for each round's results instead "
      "of blocking: 100% of one CPU, almost all of it waiting",
      "busy_wait,cpu_hog", "thread_differences" },
    { "cpu_starvation",
      "every 5 s a monitor thread (SCHED_FIFO 10) on calc-3's CPU spins for 2 s; calc-3 is "
      "runnable but barely runs, and its rounds stretch to ~1 s",
      "cpu_starvation,scheduling_delay,barrier_straggler,bottleneck_thread",
      "one_off_delay,tail_latency,long_blocked_waits,thread_differences,rt_preempted" },
    { "oversubscription",
      "32 calc threads share 4 CPUs (the healthy run has 8 threads on 8 CPUs), each with 10 ms "
      "of work per round; they wait in the run queues",
      "oversubscription,scheduling_delay", "cpu_hog,excessive_migrations,jitter" },
    { "migrations",
      "each calc thread moves itself to the next CPU (sched_setaffinity) after every 1 ms of "
      "work: ~800 migrations per second",
      "excessive_migrations", "many_small_calls,scheduling_delay" },
    { "odd_worker",
      "calc-6 also writes 200 small log lines (write(), 64 bytes each) after its CPU work, every "
      "round; the other calc threads only compute",
      "thread_differences", "many_small_calls,barrier_straggler,bottleneck_thread" },
};
static const bench_program program = {
    "crunch",
    "every 100 ms a coordinator gives 8 calc threads (one per CPU) 10 ms of CPU work each and "
    "waits for all of them",
    faults, sizeof faults / sizeof faults[0],
};

static int nworkers = 8;
static sem_t start_sem[MAX_WORKERS], round_done;
static atomic_int remaining, quitting, results_ready;
static int64_t round_start;
static int log_fd = -1;

#define MAX_ROUNDS 100000
static double round_ms[MAX_ROUNDS];
static int rounds, overruns;

static void record_metrics(void) {
    int n = rounds < MAX_ROUNDS ? rounds : MAX_ROUNDS;
    b_metric("rounds", rounds);
    b_metric("overruns", overruns);
    b_metric("calc_threads", nworkers);
    b_metric("round_ms_mean", b_mean(round_ms, n));
    b_metric("round_ms_p50", b_quantile(round_ms, n, 0.5));
    b_metric("round_ms_p99", b_quantile(round_ms, n, 0.99));
    b_metric("round_ms_max", b_quantile(round_ms, n, 1.0));
}

static int worker_cpu(int id) {
    if (b_fault_is("oversubscription")) return B.cpu + id % 4;
    return B.cpu + id;
}

static void *worker_main(void *arg) {
    int id = (int)(intptr_t)arg;
    char name[16];
    snprintf(name, sizeof name, "calc-%d", id);
    b_thread_start(name, "calc thread");
    b_pin(worker_cpu(id));
    double work = b_fault_is("load_imbalance") && id == 0 ? 4 * WORK_MS : WORK_MS;
    int cpu_index = id;
    for (;;) {
        sem_wait(&start_sem[id]);
        if (atomic_load(&quitting)) break;
        if (b_fault_is("migrations")) {
            for (int k = 0; k < 10; k++) {
                b_burn_ms(work / 10);
                cpu_index = (cpu_index + 1) % 8;
                b_pin(B.cpu + cpu_index);
            }
        } else {
            b_burn_ms(work);
        }
        if (b_fault_is("odd_worker") && id == 6) {
            char line[64];
            memset(line, '.', sizeof line - 1);
            line[sizeof line - 1] = '\n';
            for (int k = 0; k < 200; k++)
                if (write(log_fd, line, sizeof line) < 0) break;
        }
        b_series("finish_ms", round_start, (double)(b_mono() - round_start) / 1e6);
        if (atomic_fetch_sub(&remaining, 1) == 1) sem_post(&round_done);
    }
    return NULL;
}

/* Spins on the CPU of `victim` at SCHED_FIFO 10: straggler (each round) or starvation. */
static void *monitor_main(void *arg) {
    int victim = (int)(intptr_t)arg;
    b_thread_start("monitor", "health monitor");
    b_pin(worker_cpu(victim));
    b_fifo(10);
    if (b_fault_is("barrier_straggler")) {
        int64_t tick = (int64_t)(TICK_MS * 1e6);
        for (int64_t t = B.start_mono + 100000000LL + 500000; t < B.end_mono; t += tick) {
            b_sleep_until(t);
            int64_t t0 = b_mono();
            b_spin_ms(20);
            b_interval("cpu_burst", t0, b_mono(), "spins 20 ms at SCHED_FIFO 10 on calc-%d's CPU",
                       victim);
        }
    } else {
        for (int64_t t = B.start_mono + 3000000000LL; t + 2000000000LL < B.end_mono;
             t += 5000000000LL) {
            b_sleep_until(t);
            int64_t t0 = b_mono();
            b_spin_ms(2000);
            b_interval("cpu_burst", t0, b_mono(),
                       "spins 2 s at SCHED_FIFO 10 on calc-%d's CPU", victim);
        }
    }
    return NULL;
}

static void *indexer_main(void *arg) {
    (void)arg;
    b_thread_start("indexer", "builds the search index");
    b_pin(B.cpu + 8);
    int64_t t0 = b_mono();
    while (b_running()) b_burn_ms(10);
    b_interval("cpu_busy", t0, b_mono(), "computes without pause on its own CPU");
    return NULL;
}

static void *collector_main(void *arg) {
    (void)arg;
    b_thread_start("collector", "collects each round's results");
    b_pin(B.cpu + 8);
    int64_t t0 = b_mono();
    long spins = 0;
    while (b_running()) {
        while (!atomic_load(&results_ready) && b_running()) spins++;
        atomic_store(&results_ready, 0);
        b_burn_ms(0.1);
    }
    b_interval("spin_wait", t0, b_mono(), "spin-waits on a flag for each round's results");
    b_metric("collector_spin_iterations", (double)spins);
    return NULL;
}

int main(int argc, char **argv) {
    b_init(argc, argv, &program, 4);
    b_before_finish = record_metrics;
    if (b_fault_is("oversubscription")) nworkers = 32;
    if (b_fault_is("odd_worker")) {
        b_mkdirs(B.data_dir);
        char path[4096];
        snprintf(path, sizeof path, "%s/calc.log", B.data_dir);
        log_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (log_fd < 0) { perror(path); return 1; }
    }
    for (int i = 0; i < nworkers; i++) sem_init(&start_sem[i], 0, 0);
    sem_init(&round_done, 0, 0);
    pthread_t workers[MAX_WORKERS], extra = 0;
    for (int i = 0; i < nworkers; i++) workers[i] = b_spawn(worker_main, (void *)(intptr_t)i);
    if (b_fault_is("barrier_straggler")) extra = b_spawn(monitor_main, (void *)(intptr_t)5);
    if (b_fault_is("cpu_starvation")) extra = b_spawn(monitor_main, (void *)(intptr_t)3);
    if (b_fault_is("cpu_hog")) extra = b_spawn(indexer_main, NULL);
    if (b_fault_is("busy_wait")) extra = b_spawn(collector_main, NULL);

    int64_t tick = (int64_t)(TICK_MS * 1e6);
    int64_t next = B.start_mono + tick;
    while (next < B.end_mono && !b_stop_requested) {
        b_sleep_until(next);
        round_start = b_mono();
        atomic_store(&remaining, nworkers);
        for (int i = 0; i < nworkers; i++) sem_post(&start_sem[i]);
        sem_wait(&round_done);
        int64_t end = b_mono();
        atomic_store(&results_ready, 1);
        double ms = (double)(end - round_start) / 1e6;
        if (rounds < MAX_ROUNDS) round_ms[rounds] = ms;
        rounds++;
        b_series("round_ms", round_start, ms);
        next += tick;
        if (end > next) { overruns++; while (next < end) next += tick; }
    }
    atomic_store(&quitting, 1);
    for (int i = 0; i < nworkers; i++) sem_post(&start_sem[i]);
    for (int i = 0; i < nworkers; i++) pthread_join(workers[i], NULL);
    if (extra) pthread_join(extra, NULL);
    printf("[crunch] %d rounds, %d overruns\n", rounds, overruns);
    b_finish();
    return 0;
}
