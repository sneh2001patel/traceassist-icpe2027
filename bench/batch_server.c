/*
 * batch_server: a coordinator hands one batch per round to four workers and waits for all of
 * them (the round is as slow as its slowest worker). worker-2 commits each round's results
 * under cache_lock; the flusher takes cache_lock at the start of every round to write back the
 * previous batch. The CASCON workload (CASCON/Experiment/batch_server.c), rebuilt with a fault
 * switch for the waiting and synchronization symptoms.
 *
 * Healthy: each worker does 5 ms of CPU work; the flusher holds cache_lock for 0.2 ms of CPU
 * work; 20 ms between rounds. All threads are pinned to one CPU (--cpu), as in CASCON, to
 * avoid Trace Compass's cross-CPU wake-up misattribution (critical_path_bug_report.md,
 * "Finding 2"), except where a fault needs the workers to run in parallel.
 *
 * Build: make batch_server        Run: ./batch_server --fault holder_sleeps -d 30s -o gt/
 */
#include "bench.h"
#include <semaphore.h>

#define WORKERS 4
#define COMMITTER 2   /* worker-2 commits under cache_lock */
#define WORK_MS 5.0
#define GAP_MS 20.0

static const bench_fault faults[] = {
    { "holder_sleeps",
      "the flusher holds cache_lock across a 40 ms sleep every round; worker-2 blocks on "
      "cache_lock (futex) and every round waits for worker-2 (batch_server <- worker-2 <- "
      "flusher <- timer)",
      "lock_holder_blocking,long_blocked_waits,bottleneck_thread,thread_differences",
      "lock_contention,slow_syscalls" },
    { "contention",
      "each worker, on its own CPU, does its 5 ms as 40 short critical sections on one shared "
      "stats_lock, so the workers keep blocking on each other for short futex waits",
      "lock_contention", "convoy,bottleneck_thread,many_small_calls,long_blocked_waits" },
    { "convoy",
      "each worker, on its own CPU, holds one global lock for its whole 5 ms of work, so the "
      "four workers run one after another instead of in parallel",
      "convoy,lock_contention", "long_blocked_waits,bottleneck_thread" },
    { "deadlock",
      "at 40% of the run, worker-1 takes lock A then B while worker-3 takes B then A; both "
      "block forever, and the coordinator waits forever for the round",
      "deadlock,hang,long_blocked_waits", "bottleneck_thread,never_exits,thread_differences" },
    { "hang",
      "at 40% of the run, worker-3 blocks forever reading a pipe nobody writes to; the "
      "coordinator waits forever for the round (no lock cycle)",
      "hang,long_blocked_waits", "bottleneck_thread,never_exits,thread_differences" },
    { "priority_inversion",
      "on one CPU: worker-2 (SCHED_FIFO 10) needs cache_lock, held by the flusher (FIFO 1), "
      "which is preempted by the compactor (FIFO 5) burning 15 ms; worker-2 waits for the "
      "medium-priority thread",
      "priority_inversion,long_blocked_waits,bottleneck_thread,thread_differences",
      "lock_holder_blocking,scheduling_delay,cpu_starvation,lock_contention" },
};
static const bench_program program = {
    "batch_server",
    "a coordinator hands one batch per round to 4 workers and waits for all of them; worker-2 "
    "commits results under cache_lock, which a flusher thread also takes every round",
    faults, sizeof faults / sizeof faults[0],
};

static sem_t start_sem[WORKERS], round_done, flush_go, flush_locked, compact_go;
static atomic_int remaining;
static atomic_int quitting;
static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t big_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lock_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lock_b = PTHREAD_MUTEX_INITIALIZER;
static int never_written[2];
static long stats_total;
static atomic_long contended, acquisitions;

#define MAX_ROUNDS 200000
static double round_ms[MAX_ROUNDS];
static int rounds;

static void record_metrics(void) {
    int n = rounds < MAX_ROUNDS ? rounds : MAX_ROUNDS;
    b_metric("rounds", rounds);
    b_metric("round_ms_mean", b_mean(round_ms, n));
    b_metric("round_ms_p50", b_quantile(round_ms, n, 0.5));
    b_metric("round_ms_p99", b_quantile(round_ms, n, 0.99));
    b_metric("lock_acquisitions", (double)atomic_load(&acquisitions));
    b_metric("lock_acquisitions_contended", (double)atomic_load(&contended));
}

static int parallel_workers(void) { return b_fault_is("contention") || b_fault_is("convoy"); }

/* Lock, recording how long the wait was. */
static double timed_lock(pthread_mutex_t *m, const char *what) {
    if (pthread_mutex_trylock(m) == 0) { atomic_fetch_add(&acquisitions, 1); return 0; }
    atomic_fetch_add(&contended, 1);
    atomic_fetch_add(&acquisitions, 1);
    int64_t t0 = b_mono();
    pthread_mutex_lock(m);
    int64_t t1 = b_mono();
    double ms = (double)(t1 - t0) / 1e6;
    if (ms >= 1.0) b_interval("lock_wait", t0, t1, "waited %.2f ms for %s", ms, what);
    return ms;
}

static void *worker_main(void *arg) {
    int id = (int)(intptr_t)arg;
    char name[16];
    snprintf(name, sizeof name, "worker-%d", id);
    b_thread_start(name, id == COMMITTER ? "worker; commits results under cache_lock" : "worker");
    b_pin(parallel_workers() ? B.cpu + id : B.cpu);
    if (b_fault_is("priority_inversion") && id == COMMITTER) b_fifo(10);
    int stuck = 0;
    for (;;) {
        sem_wait(&start_sem[id]);
        if (atomic_load(&quitting)) break;
        int64_t t0 = b_mono();
        if (b_fault_is("deadlock") && t0 >= b_at(0.4) && (id == 1 || id == 3)) {
            pthread_mutex_t *first = id == 1 ? &lock_a : &lock_b;
            pthread_mutex_t *second = id == 1 ? &lock_b : &lock_a;
            pthread_mutex_lock(first);
            b_sleep_ms(2);
            b_interval("deadlock", b_mono(), B.end_mono,
                       "holds lock %s, blocks forever on lock %s (held by worker-%d)",
                       id == 1 ? "A" : "B", id == 1 ? "B" : "A", id == 1 ? 3 : 1);
            pthread_mutex_lock(second); /* never returns */
        }
        if (b_fault_is("hang") && t0 >= b_at(0.4) && id == 3 && !stuck) {
            stuck = 1;
            char c;
            b_interval("blocked_forever", b_mono(), B.end_mono,
                       "blocks forever in read() on a pipe nobody writes to");
            if (read(never_written[0], &c, 1) < 0) {} /* never returns */
        }
        double lock_wait = 0;
        if (b_fault_is("priority_inversion") && id == COMMITTER) {
            lock_wait = timed_lock(&cache_lock, "cache_lock (held by the flusher)");
            b_burn_ms(0.2);
            pthread_mutex_unlock(&cache_lock);
            b_burn_ms(WORK_MS);
        } else if (b_fault_is("contention")) {
            double waited = 0;
            for (int k = 0; k < 40; k++) {
                waited += timed_lock(&stats_lock, "stats_lock");
                b_burn_ms(WORK_MS / 40 * 0.8);
                stats_total++;
                pthread_mutex_unlock(&stats_lock);
                b_burn_ms(WORK_MS / 40 * 0.2);
            }
            b_series("stats_lock_wait_ms", t0, waited);
        } else if (b_fault_is("convoy")) {
            double waited = timed_lock(&big_lock, "the global lock");
            b_burn_ms(WORK_MS);
            pthread_mutex_unlock(&big_lock);
            b_series("global_lock_wait_ms", t0, waited);
        } else {
            b_burn_ms(WORK_MS);
            if (id == COMMITTER) {
                lock_wait = timed_lock(&cache_lock, "cache_lock (held by the flusher)");
                b_burn_ms(0.2);
                pthread_mutex_unlock(&cache_lock);
            }
        }
        if (id == COMMITTER) b_series("worker2_cache_lock_wait_ms", t0, lock_wait);
        b_series("worker_busy_ms", t0, (double)(b_mono() - t0) / 1e6);
        if (atomic_fetch_sub(&remaining, 1) == 1) sem_post(&round_done);
    }
    return NULL;
}

static void *flusher_main(void *arg) {
    (void)arg;
    b_thread_start("flusher", "writes back the previous batch under cache_lock every round");
    b_pin(B.cpu);
    if (b_fault_is("priority_inversion")) b_fifo(1);
    for (;;) {
        sem_wait(&flush_go);
        if (atomic_load(&quitting)) break;
        pthread_mutex_lock(&cache_lock);
        int64_t t0 = b_mono();
        if (b_fault_is("holder_sleeps")) {
            b_sleep_ms(40);
            b_interval("lock_held", t0, b_mono(), "holds cache_lock across a 40 ms sleep");
        } else if (b_fault_is("priority_inversion")) {
            sem_post(&flush_locked);
            b_burn_ms(3);
            int64_t t1 = b_mono();
            b_interval("lock_held", t0, t1, "holds cache_lock for 3 ms of CPU work, %.1f ms wall "
                       "(preempted by the compactor)", (double)(t1 - t0) / 1e6);
        } else {
            b_burn_ms(0.2);
        }
        pthread_mutex_unlock(&cache_lock);
    }
    return NULL;
}

static void *compactor_main(void *arg) {
    (void)arg;
    b_thread_start("compactor", "compacts the cache once per round (15 ms of CPU work)");
    b_pin(B.cpu);
    b_fifo(5);
    for (;;) {
        sem_wait(&compact_go);
        if (atomic_load(&quitting)) break;
        int64_t t0 = b_mono();
        b_burn_ms(15);
        b_interval("compaction", t0, b_mono(), "15 ms of CPU work at SCHED_FIFO 5");
    }
    return NULL;
}

int main(int argc, char **argv) {
    b_init(argc, argv, &program, 3);
    if (b_fault_is("deadlock") || b_fault_is("hang")) b_watchdog_grace_s = 0.2;
    b_pin(B.cpu);
    if (b_fault_is("priority_inversion")) b_fifo(30); /* only posts and waits */
    if (pipe(never_written) != 0) { perror("pipe"); return 1; }
    for (int i = 0; i < WORKERS; i++) sem_init(&start_sem[i], 0, 0);
    sem_init(&round_done, 0, 0);
    sem_init(&flush_go, 0, 0);
    sem_init(&flush_locked, 0, 0);
    sem_init(&compact_go, 0, 0);
    pthread_t workers[WORKERS], flusher, compactor = 0;
    for (int i = 0; i < WORKERS; i++) workers[i] = b_spawn(worker_main, (void *)(intptr_t)i);
    flusher = b_spawn(flusher_main, NULL);
    if (b_fault_is("priority_inversion")) compactor = b_spawn(compactor_main, NULL);
    b_before_finish = record_metrics;
    b_sleep_ms(100);

    while (b_running()) {
        int64_t t0 = b_mono();
        atomic_store(&remaining, WORKERS);
        sem_post(&flush_go);
        if (b_fault_is("priority_inversion")) {
            sem_wait(&flush_locked); /* the flusher holds cache_lock */
            for (int i = 0; i < WORKERS; i++) sem_post(&start_sem[i]);
            sem_post(&compact_go);
        } else {
            for (int i = 0; i < WORKERS; i++) sem_post(&start_sem[i]);
        }
        sem_wait(&round_done); /* deadlock / hang: never returns, the watchdog ends the run */
        int64_t t1 = b_mono();
        double ms = (double)(t1 - t0) / 1e6;
        if (rounds < MAX_ROUNDS) round_ms[rounds] = ms;
        rounds++;
        b_series("round_ms", t0, ms);
        b_sleep_ms(GAP_MS);
    }
    atomic_store(&quitting, 1);
    for (int i = 0; i < WORKERS; i++) sem_post(&start_sem[i]);
    sem_post(&flush_go);
    sem_post(&compact_go);
    for (int i = 0; i < WORKERS; i++) pthread_join(workers[i], NULL);
    pthread_join(flusher, NULL);
    if (compactor) pthread_join(compactor, NULL);

    int n = rounds < MAX_ROUNDS ? rounds : MAX_ROUNDS;
    printf("[batch_server] %d rounds, mean %.2f ms, p99 %.2f ms\n", rounds,
           b_mean(round_ms, n), b_quantile(round_ms, n, 0.99));
    b_finish();
    return 0;
}
