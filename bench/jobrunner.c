/*
 * jobrunner: a dispatcher queues a job every 10 ms (100 per second) for a pool of four job
 * threads (job-0..3); each job is 2 ms of CPU work. Start-up takes ~20 ms and shutdown is
 * immediate. New workload, for the process lifecycle symptoms.
 *
 * Build: make jobrunner        Run: ./jobrunner --fault crash -d 30s -o gt/
 */
#include "bench.h"
#include <sys/resource.h>
#include <sys/wait.h>

#define POOL 4

static const bench_fault faults[] = {
    { "slow_startup",
      "before running any job, start-up spends 1.5 s of CPU on initialisation and then waits "
      "1.5 s: the first job runs ~3 s after the start (the healthy start-up takes ~20 ms)",
      "slow_startup", "long_blocked_waits" },
    { "slow_shutdown",
      "at the end of the run each job thread, one after another, holds a shared lock for 1.5 s "
      "while it flushes its state: the process takes ~6 s to exit after its last job",
      "slow_shutdown", "long_blocked_waits,lock_holder_blocking,convoy" },
    { "crash",
      "every 5 s the dispatcher forks a helper process (job-helper) for a batch; the third "
      "helper dies of a segmentation fault (SIGSEGV) instead of exiting normally; the "
      "dispatcher carries on",
      "crash", "" },
    { "fork_storm",
      "every job runs a short-lived process (fork + exec of /usr/bin/true) instead of running "
      "in the pool thread: ~100 processes started per second",
      "fork_exec_storm", "many_small_calls" },
    { "thread_churn",
      "every job runs on a brand-new thread, created and joined by the dispatcher, instead of "
      "the pool: ~100 threads created per second",
      "thread_churn", "" },
    { "never_exits",
      "at 40% of the run all jobs are done and the dispatcher shuts the pool down, but job-2 "
      "is blocked forever reading a pipe nobody writes to, so the process never exits; it sits "
      "idle until the end of the run",
      "never_exits", "hang,long_blocked_waits,idle_thread" },
};
static const bench_program program = {
    "jobrunner",
    "a dispatcher queues a 2 ms CPU job every 10 ms for a pool of 4 job threads",
    faults, sizeof faults / sizeof faults[0],
};

static pthread_mutex_t q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_cond = PTHREAD_COND_INITIALIZER;
static int q_jobs, q_closed;
static pthread_mutex_t flush_lock = PTHREAD_MUTEX_INITIALIZER;
static int never_written[2];
static atomic_long jobs_done, processes, threads_created;
static int64_t first_job = 0;

static void record_metrics(void) {
    b_metric("jobs_done", (double)atomic_load(&jobs_done));
    b_metric("processes_started", (double)atomic_load(&processes));
    b_metric("threads_created", (double)atomic_load(&threads_created));
    if (first_job) b_metric("first_job_s", b_rel(first_job));
}

static void run_job(void) {
    if (b_fault_is("fork_storm")) {
        pid_t p = fork();
        if (p == 0) { execl("/usr/bin/true", "true", (char *)NULL); _exit(127); }
        if (p > 0) waitpid(p, NULL, 0);
        atomic_fetch_add(&processes, 1);
    } else {
        b_burn_ms(2);
    }
    atomic_fetch_add(&jobs_done, 1);
}

static void *pool_main(void *arg) {
    int id = (int)(intptr_t)arg;
    char name[16];
    snprintf(name, sizeof name, "job-%d", id);
    b_thread_start(name, "pool thread: runs jobs");
    b_pin(B.cpu + id);
    for (;;) {
        pthread_mutex_lock(&q_lock);
        while (q_jobs == 0 && !q_closed) pthread_cond_wait(&q_cond, &q_lock);
        if (q_jobs == 0) { pthread_mutex_unlock(&q_lock); break; }
        q_jobs--;
        pthread_mutex_unlock(&q_lock);
        run_job();
    }
    if (b_fault_is("never_exits") && id == 2) {
        char c;
        b_interval("blocked_forever", b_mono(), B.end_mono,
                   "waits forever in read() for a final acknowledgement nobody sends");
        if (read(never_written[0], &c, 1) < 0) {}
    }
    if (b_fault_is("slow_shutdown")) {
        pthread_mutex_lock(&flush_lock);
        int64_t t0 = b_mono();
        b_sleep_ms(1500);
        b_interval("shutdown_flush", t0, b_mono(), "flushes its state for 1.5 s holding the "
                   "shared flush lock");
        pthread_mutex_unlock(&flush_lock);
    }
    return NULL;
}

static void *oneshot_main(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "job-worker", 0, 0, 0);
    run_job();
    return NULL;
}

static void helper_process(int n) {
    prctl(PR_SET_NAME, "job-helper", 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0); /* no core dump, no coredump helper in the trace */
    b_thread_start("job-helper", "helper process: processes one batch");
    b_burn_ms(50);
    if (n == 3) {
        b_interval("crash", b_mono(), b_mono(), "helper process %d dies of SIGSEGV", getpid());
        volatile int *p = NULL;
        *p = 1;
    }
    _exit(0);
}

int main(int argc, char **argv) {
    b_init(argc, argv, &program, 3);
    b_before_finish = record_metrics;
    if (b_fault_is("never_exits")) b_watchdog_grace_s = 0.2;
    if (pipe(never_written) != 0) return 1;
    int64_t t0 = b_mono();
    if (b_fault_is("slow_startup")) {
        b_burn_ms(1500);
        b_sleep_ms(1500);
    } else {
        b_burn_ms(20);
    }
    pthread_t pool[POOL];
    for (int i = 0; i < POOL; i++) pool[i] = b_spawn(pool_main, (void *)(intptr_t)i);
    b_interval("startup", t0, b_mono(), "start-up, until the first job is queued");

    int64_t next = b_mono(), next_helper = b_mono() + 5000000000LL;
    int helpers = 0;
    double stop_at = b_fault_is("never_exits") ? 0.4 : 1.0;
    while (b_running() && b_mono() < b_at(stop_at)) {
        if (!first_job) first_job = b_mono();
        if (b_fault_is("thread_churn")) {
            pthread_t t;
            if (pthread_create(&t, NULL, oneshot_main, NULL) == 0) {
                pthread_join(t, NULL);
                atomic_fetch_add(&threads_created, 1);
            }
        } else {
            pthread_mutex_lock(&q_lock);
            q_jobs++;
            pthread_cond_signal(&q_cond);
            pthread_mutex_unlock(&q_lock);
        }
        if (b_fault_is("crash") && b_mono() >= next_helper) {
            helpers++;
            pid_t p = fork();
            if (p == 0) helper_process(helpers);
            int status = 0;
            waitpid(p, &status, 0);
            atomic_fetch_add(&processes, 1);
            if (WIFSIGNALED(status)) {
                printf("[jobrunner] helper %d (pid %d) was killed by signal %d\n", helpers, p,
                       WTERMSIG(status));
                b_metric("crashed_helper_pid", p);
                b_metric("crashed_helper_signal", WTERMSIG(status));
            }
            next_helper += 5000000000LL;
        }
        next += 10000000;
        b_sleep_until(next);
    }
    int64_t s0 = b_mono();
    pthread_mutex_lock(&q_lock);
    q_closed = 1;
    pthread_cond_broadcast(&q_cond);
    pthread_mutex_unlock(&q_lock);
    if (b_fault_is("never_exits"))
        b_interval("shutdown_started", s0, s0, "all jobs done; waiting for the pool to exit");
    for (int i = 0; i < POOL; i++) pthread_join(pool[i], NULL); /* never_exits: never returns */
    b_interval("shutdown", s0, b_mono(), "from the last job to the end of the process");
    printf("[jobrunner] %ld jobs\n", atomic_load(&jobs_done));
    b_finish();
    return 0;
}
