/*
 * reporter: a render thread produces a report every 50 ms (8 ms of CPU work), pinned to one
 * CPU (--cpu); the main thread wakes once a second. New workload, for the noisy neighbour.
 *
 * neighbour starts a separate process (indexd, forked; not a thread of reporter) with three
 * CPU-bound threads pinned to the render thread's CPU, from 30% to 80% of the run. The render
 * thread records each report's wall time (report_ms).
 *
 * irq_storm adds an archive thread, also on render's CPU, that from 30% to 70% of the run re-reads
 * the stored reports with direct (uncached) 4 KB reads, 64 in flight at a time. The machine's NVMe
 * drives have one completion interrupt per CPU, raised on the CPU that issued the read, so every
 * completion interrupts render's CPU: a few hundred thousand device interrupts a second, about a
 * fifth of that CPU. The data file is written (and synced) before the storm starts, so the reads
 * really reach the disk.
 *
 * Build: make reporter        Run: ./reporter --fault neighbour -d 30s -o gt/
 */
#include "bench.h"
#include <linux/aio_abi.h>
#include <sys/wait.h>

static const bench_fault faults[] = {
    { "neighbour",
      "from 30% to 80% of the run a separate process, indexd, runs three CPU-bound threads on "
      "the render thread's CPU; render only gets a quarter of its CPU and each report takes "
      "~4x longer",
      "noisy_neighbour,scheduling_delay",
      "cpu_hog,oversubscription,sudden_change,jitter,tail_latency" },
    { "irq_storm",
      "from 30% to 70% of the run an archive thread on render's CPU re-reads stored reports with "
      "direct 4 KB reads, 64 in flight; their completion interrupts land on render's CPU, taking "
      "about a fifth of it, and each report takes longer",
      "interrupt_storm",
      "sudden_change,jitter,tail_latency,scheduling_delay,waiting_on_disk,many_small_calls,"
      "slow_syscalls,unexpected_activity,thread_differences" },
};
static const bench_program program = {
    "reporter",
    "a render thread produces a report every 50 ms (8 ms of CPU work) on one CPU",
    faults, sizeof faults / sizeof faults[0],
};

#define MAX_REPORTS 100000
static double report_ms[MAX_REPORTS];
static int64_t report_t0[MAX_REPORTS];
static int reports;
static int64_t storm_t0, storm_t1;

static void record_metrics(void) {
    int n = reports < MAX_REPORTS ? reports : MAX_REPORTS;
    b_metric("reports", reports);
    b_metric("report_ms_mean", b_mean(report_ms, n));
    b_metric("report_ms_p50", b_quantile(report_ms, n, 0.5));
    b_metric("report_ms_max", b_quantile(report_ms, n, 1.0));
    if (storm_t1 > storm_t0) {
        static double in[MAX_REPORTS], out[MAX_REPORTS];
        int ni = 0, no = 0;
        for (int i = 0; i < n; i++) {
            if (report_t0[i] >= storm_t0 && report_t0[i] < storm_t1) in[ni++] = report_ms[i];
            else out[no++] = report_ms[i];
        }
        b_metric("report_ms_mean_during_storm", b_mean(in, ni));
        b_metric("report_ms_mean_outside_storm", b_mean(out, no));
    }
}

static void *render_main(void *arg) {
    (void)arg;
    b_thread_start("render", "produces a report every 50 ms");
    b_pin(B.cpu);
    int64_t next = b_mono();
    while (b_running()) {
        next += 50000000;
        b_sleep_until(next);
        int64_t t0 = b_mono();
        b_burn_ms(8);
        double ms = (double)(b_mono() - t0) / 1e6;
        if (reports < MAX_REPORTS) { report_ms[reports] = ms; report_t0[reports] = t0; }
        reports++;
        b_series("report_ms", t0, ms);
        if (b_mono() > next) next = b_mono();
    }
    return NULL;
}

static void *spin_main(void *arg) {
    int id = (int)(intptr_t)arg;
    char name[16];
    snprintf(name, sizeof name, "indexd-%d", id);
    b_thread_start(name, "separate process indexd: CPU-bound indexing");
    b_pin(B.cpu);
    for (;;) b_burn_ms(10);
    return NULL;
}

/* ---------------------------------------------------------------- irq_storm */

#define ARCHIVE_MB 512
#define ARCHIVE_QD 64
#define ARCHIVE_BATCH 16
static int64_t archive_reads;

static long sys_io_setup(unsigned n, aio_context_t *ctx) { return syscall(SYS_io_setup, n, ctx); }
static long sys_io_submit(aio_context_t ctx, long n, struct iocb **v) {
    return syscall(SYS_io_submit, ctx, n, v);
}
static long sys_io_getevents(aio_context_t ctx, long min, long max, struct io_event *ev) {
    return syscall(SYS_io_getevents, ctx, min, max, ev, NULL);
}

/* Writes the archive file (ARCHIVE_MB of non-zero data, synced) and returns its fd for
   direct reads. */
static int archive_open(void) {
    char path[4096];
    b_mkdirs(B.data_dir);
    snprintf(path, sizeof path, "%s/reports.dat", B.data_dir);
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) { perror(path); exit(1); }
    size_t chunk = 4 << 20;
    char *buf = malloc(chunk);
    for (size_t i = 0; i < chunk; i++) buf[i] = (char)(i * 131 + 7);
    for (int i = 0; i < ARCHIVE_MB / 4; i++)
        if (write(fd, buf, chunk) != (ssize_t)chunk) { perror("write"); exit(1); }
    fsync(fd);
    close(fd);
    free(buf);
    fd = open(path, O_RDONLY | O_DIRECT);
    if (fd < 0) { perror(path); exit(1); }
    return fd;
}

static void *archive_main(void *arg) {
    (void)arg;
    b_thread_start("archive", "keeps the stored reports and re-reads them");
    b_pin(B.cpu);
    int fd = archive_open();
    char *bufs;
    if (posix_memalign((void **)&bufs, 4096, 4096 * ARCHIVE_QD)) exit(1);
    aio_context_t ctx = 0;
    if (sys_io_setup(ARCHIVE_QD, &ctx) < 0) { perror("io_setup"); exit(1); }
    struct iocb cbs[ARCHIVE_QD], *ptrs[ARCHIVE_QD];
    struct io_event ev[ARCHIVE_QD];
    uint64_t blocks = (uint64_t)ARCHIVE_MB * 256, x = 88172645463325252ULL;

    b_sleep_until(b_at(0.3));
    storm_t0 = b_mono();
    int inflight = 0, slot[ARCHIVE_QD], nfree = ARCHIVE_QD;
    for (int i = 0; i < ARCHIVE_QD; i++) slot[i] = i;
    while (b_running() && b_mono() < b_at(0.7)) {
        int n = 0;
        while (nfree > 0) {
            int k = slot[--nfree];
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            memset(&cbs[k], 0, sizeof cbs[k]);
            cbs[k].aio_data = (uint64_t)k;
            cbs[k].aio_lio_opcode = IOCB_CMD_PREAD;
            cbs[k].aio_fildes = (uint32_t)fd;
            cbs[k].aio_buf = (uint64_t)(uintptr_t)(bufs + 4096 * k);
            cbs[k].aio_nbytes = 4096;
            cbs[k].aio_offset = (int64_t)((x % blocks) * 4096);
            ptrs[n++] = &cbs[k];
        }
        if (n && sys_io_submit(ctx, n, ptrs) != n) { perror("io_submit"); exit(1); }
        inflight += n;
        long got = sys_io_getevents(ctx, ARCHIVE_BATCH, ARCHIVE_QD, ev);
        if (got < 0) { if (errno == EINTR) continue; perror("io_getevents"); exit(1); }
        for (long i = 0; i < got; i++) slot[nfree++] = (int)ev[i].data;
        inflight -= (int)got;
        archive_reads += got;
    }
    while (inflight > 0) {
        long got = sys_io_getevents(ctx, 1, ARCHIVE_QD, ev);
        if (got > 0) inflight -= (int)got;
        else if (errno != EINTR) break;
    }
    storm_t1 = b_mono();
    b_interval("interrupt_storm", storm_t0, storm_t1, "archive's %lld direct 4 KB reads complete "
               "with device interrupts on render's CPU %d", (long long)archive_reads, B.cpu);
    close(fd);
    while (b_running()) b_sleep_ms(1000);
    return NULL;
}

static void neighbour_process(void) {
    signal(SIGTERM, SIG_DFL);
    prctl(PR_SET_NAME, "indexd", 0, 0, 0);
    b_thread_start("indexd", "separate process indexd: main thread");
    for (int i = 0; i < 3; i++) b_spawn(spin_main, (void *)(intptr_t)i);
    for (;;) pause();
}

int main(int argc, char **argv) {
    b_init(argc, argv, &program, 3);
    b_before_finish = record_metrics;
    pthread_t r = b_spawn(render_main, NULL);
    pthread_t a = 0;
    if (b_fault_is("irq_storm")) a = b_spawn(archive_main, NULL);
    pid_t neighbour = 0;
    if (b_fault_is("neighbour")) {
        b_sleep_until(b_at(0.3));
        int64_t t0 = b_mono();
        neighbour = fork();
        if (neighbour == 0) neighbour_process();
        b_metric("neighbour_pid", neighbour);
        b_sleep_until(b_at(0.8));
        kill(neighbour, SIGTERM);
        waitpid(neighbour, NULL, 0);
        b_interval("neighbour_running", t0, b_mono(), "process indexd (pid %d) runs 3 CPU-bound "
                   "threads on render's CPU", neighbour);
    }
    while (b_running()) b_sleep_ms(1000);
    pthread_join(r, NULL);
    if (a) {
        pthread_join(a, NULL);
        double s = (double)(storm_t1 - storm_t0) / 1e9;
        b_metric("archive_reads", (double)archive_reads);
        b_metric("archive_reads_per_s", s > 0 ? archive_reads / s : 0);
    }
    printf("[reporter] %d reports\n", reports);
    b_finish();
    return 0;
}
