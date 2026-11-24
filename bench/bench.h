/*
 * bench.h: shared helpers for the symptom bench programs (header-only).
 *
 * Every program in this folder is one workload with a fault switch:
 *
 *     ./<program> --fault <name> -d 30s -o <ground-truth dir> [--data DIR] [--cpu N]
 *     ./<program> --list-faults          (JSON: the faults and the symptoms each one makes present)
 *
 * `--fault none` (the default) is the program's healthy baseline. The program writes its own
 * answer key to the -o directory:
 *
 *   ground_truth.json  the fault, the symptoms it makes present, the threads (name, tid), the
 *                      intervals where the fault acts, and the program's own measurements
 *   series.csv         per-iteration measurements (round times, lateness, ...), if any
 *
 * Symptom ids are the ones in symptoms.json. A symptom that is neither "present" nor
 * "dont_care" for a run is absent from the program (the harness computes "absent").
 *
 * Rules every program follows, so that the trace itself is the only evidence:
 *  - thread and file names are neutral and never name the fault;
 *  - CPU work is a calibrated arithmetic loop, never a loop around a syscall (which would
 *    leave thousands of syscalls in the trace). CLOCK_MONOTONIC reads go through the vDSO
 *    (the clocksource is TSC), so they make no syscall either;
 *  - times are CLOCK_MONOTONIC, the clock LTTng's kernel tracer uses, and the realtime
 *    offset at start is recorded too, so the intervals can be matched to the trace.
 */
#ifndef BENCH_H
#define BENCH_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#pragma GCC diagnostic ignored "-Wunused-function"

typedef struct {
    const char *name;
    const char *summary;   /* what the fault does, for the answer key */
    const char *present;   /* comma-separated symptom ids the fault makes present */
    const char *dont_care; /* ids that are arguably present too: not graded either way */
} bench_fault;

typedef struct {
    const char *name;        /* the binary's name, also the main thread's name */
    const char *description; /* the healthy workload */
    const bench_fault *faults;
    int nfaults;
} bench_program;

/* ---------------------------------------------------------------- state */

#define B_MAX_THREADS 1024
#define B_MAX_INTERVALS 16384
#define B_MAX_METRICS 256

struct b_thread { char name[16]; char role[64]; int pid, tid; };
struct b_interval { char kind[32]; char thread[16]; int tid; int64_t start, end; char note[112]; };
struct b_metric { char key[56]; double value; };

/* Shared (MAP_SHARED) so forked helper processes can register threads and intervals too. */
struct b_shared {
    atomic_int nthreads, nintervals, nmetrics, finished;
    struct b_thread threads[B_MAX_THREADS];
    struct b_interval intervals[B_MAX_INTERVALS];
    struct b_metric metrics[B_MAX_METRICS];
};

static struct {
    const bench_program *prog;
    const bench_fault *fault;
    double duration_s;
    const char *out_dir;
    const char *data_dir;
    int cpu;
    unsigned seed;
    int main_pid;
    int64_t start_mono, start_real, end_mono;
    double iters_per_ms;
    int argc;
    char **argv;
} B;

static struct b_shared *BS;
static volatile sig_atomic_t b_stop_requested;

static const bench_fault b_fault_none = {
    "none", "no fault: the program's healthy baseline", "", ""
};

/* ---------------------------------------------------------------- time */

static inline int64_t b_mono(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static inline int64_t b_real(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Seconds since the program started. */
static inline double b_rel(int64_t mono) { return (double)(mono - B.start_mono) / 1e9; }

/* The monotonic time at fraction f of the run (0 = start, 1 = end). */
static inline int64_t b_at(double f) {
    return B.start_mono + (int64_t)(f * B.duration_s * 1e9);
}

static inline int b_running(void) { return !b_stop_requested && b_mono() < B.end_mono; }

static void b_sleep_until(int64_t mono) {
    struct timespec ts = { (time_t)(mono / 1000000000LL), (long)(mono % 1000000000LL) };
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {}
}

static void b_sleep_ms(double ms) {
    if (ms > 0) b_sleep_until(b_mono() + (int64_t)(ms * 1e6));
}

/* Spin on the CPU for `ms` of wall time (no syscalls). */
static void b_spin_ms(double ms) {
    int64_t end = b_mono() + (int64_t)(ms * 1e6);
    while (b_mono() < end) {}
}

static volatile unsigned long b_sink;

static void b_loop(unsigned long n) {
    unsigned long x = b_sink + 1;
    for (unsigned long i = 0; i < n; i++) x = x * 6364136223846793005UL + 1442695040888963407UL;
    b_sink = x;
}

/* Do `ms` of CPU work (calibrated; takes longer in wall time if the thread is preempted). */
static void b_burn_ms(double ms) {
    if (ms > 0) b_loop((unsigned long)(ms * B.iters_per_ms));
}

static void b_calibrate(void) {
    unsigned long n = 100000;
    for (;;) {
        int64_t t0 = b_mono();
        b_loop(n);
        int64_t dt = b_mono() - t0;
        if (dt > 30000000) { B.iters_per_ms = (double)n / ((double)dt / 1e6); return; }
        n *= 2;
    }
}

/* ---------------------------------------------------------------- threads and CPUs */

static inline int b_tid(void) { return (int)syscall(SYS_gettid); }

static void b_pin(int cpu) {
    if (cpu < 0) return;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static void b_pin_range(int first, int count) {
    cpu_set_t set;
    CPU_ZERO(&set);
    for (int c = first; c < first + count; c++) CPU_SET(c, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static void b_unpin(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    b_pin_range(0, (int)n);
}

static void b_metric(const char *key, double value);

/* SCHED_FIFO at `prio` for the calling thread; 0 on success. */
static int b_fifo(int prio) {
    struct sched_param p = { .sched_priority = prio };
    if (sched_setscheduler(0, SCHED_FIFO, &p) == 0) return 0;
    fprintf(stderr, "warning: SCHED_FIFO %d denied (%s); the fault will be weaker\n", prio,
            strerror(errno));
    b_metric("sched_fifo_denied", 1);
    return -1;
}

/* Name the calling thread (its comm in the trace) and record it in the answer key. */
static void b_register(const char *name, const char *role) {
    prctl(PR_SET_NAME, name, 0, 0, 0);
    int i = atomic_fetch_add(&BS->nthreads, 1);
    if (i >= B_MAX_THREADS) return;
    struct b_thread *t = &BS->threads[i];
    snprintf(t->name, sizeof t->name, "%s", name);
    snprintf(t->role, sizeof t->role, "%s", role);
    t->pid = getpid();
    t->tid = b_tid();
}

/* Thread-local name, for intervals. */
static __thread char b_my_name[16];

static void b_thread_start(const char *name, const char *role) {
    snprintf(b_my_name, sizeof b_my_name, "%s", name);
    b_register(name, role);
}

/* ---------------------------------------------------------------- answer key */

/* An interval where the fault acts, or a measured event the grader can check. */
static void b_interval(const char *kind, int64_t start, int64_t end, const char *fmt, ...) {
    int i = atomic_fetch_add(&BS->nintervals, 1);
    if (i >= B_MAX_INTERVALS) return;
    struct b_interval *v = &BS->intervals[i];
    snprintf(v->kind, sizeof v->kind, "%s", kind);
    snprintf(v->thread, sizeof v->thread, "%s", b_my_name);
    v->tid = b_tid();
    v->start = start;
    v->end = end;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(v->note, sizeof v->note, fmt ? fmt : "", ap);
    va_end(ap);
}

static void b_metric(const char *key, double value) {
    for (int i = 0; i < atomic_load(&BS->nmetrics) && i < B_MAX_METRICS; i++)
        if (strcmp(BS->metrics[i].key, key) == 0) { BS->metrics[i].value = value; return; }
    int i = atomic_fetch_add(&BS->nmetrics, 1);
    if (i >= B_MAX_METRICS) return;
    snprintf(BS->metrics[i].key, sizeof BS->metrics[i].key, "%s", key);
    BS->metrics[i].value = value;
}

/* Per-iteration measurements, written to series.csv (main process only). */
struct b_row { const char *series; char thread[16]; int tid; int64_t t; double value; };
static struct b_row *b_rows;
static size_t b_nrows, b_caprows;
static pthread_mutex_t b_rows_lock = PTHREAD_MUTEX_INITIALIZER;

static void b_series(const char *series, int64_t t, double value) {
    pthread_mutex_lock(&b_rows_lock);
    if (b_nrows == b_caprows && b_caprows < 4000000) {
        size_t cap = b_caprows ? b_caprows * 2 : 65536;
        struct b_row *r = realloc(b_rows, cap * sizeof *r);
        if (r) { b_rows = r; b_caprows = cap; }
    }
    if (b_nrows < b_caprows) {
        struct b_row *r = &b_rows[b_nrows++];
        r->series = series;
        snprintf(r->thread, sizeof r->thread, "%s", b_my_name);
        r->tid = b_tid();
        r->t = t;
        r->value = value;
    }
    pthread_mutex_unlock(&b_rows_lock);
}

static void b_json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') fprintf(f, "\\%c", *s);
        else if ((unsigned char)*s < 0x20) fprintf(f, "\\u%04x", *s);
        else fputc(*s, f);
    }
    fputc('"', f);
}

static void b_json_ids(FILE *f, const char *csv) {
    fputc('[', f);
    int first = 1;
    const char *p = csv;
    while (p && *p) {
        const char *q = strchr(p, ',');
        size_t n = q ? (size_t)(q - p) : strlen(p);
        while (n && *p == ' ') { p++; n--; }
        if (n) {
            fprintf(f, "%s\"%.*s\"", first ? "" : ", ", (int)n, p);
            first = 0;
        }
        p = q ? q + 1 : NULL;
    }
    fputc(']', f);
}

static void b_mkdirs(const char *path) {
    char buf[4096];
    snprintf(buf, sizeof buf, "%s", path);
    for (char *p = buf + 1; *p; p++)
        if (*p == '/') { *p = 0; mkdir(buf, 0755); *p = '/'; }
    mkdir(buf, 0755);
}

static pthread_mutex_t b_finish_lock = PTHREAD_MUTEX_INITIALIZER;

/* Called first by b_finish (also when the watchdog ends the run): record final metrics here. */
static void (*b_before_finish)(void);

/*
 * The answer key's files. capture.sh passes them as pipes it opened before tracing started
 * (BENCH_KEY_FD, BENCH_SERIES_FD), so the trace shows the program writing to two anonymous pipes,
 * not to files named ground_truth.json and series.csv; run by hand, they are files in -o DIR.
 */
static FILE *b_open_key(const char *env, const char *name, char *path, size_t size) {
    const char *fd = getenv(env);
    if (fd && *fd) {
        snprintf(path, size, "fd %s", fd);
        return fdopen(atoi(fd), "w");
    }
    snprintf(path, size, "%s/%s", B.out_dir, name);
    return fopen(path, "w");
}

/* Write ground_truth.json and series.csv. Safe to call more than once; the first call wins. */
static void b_finish(void) {
    if (getpid() != B.main_pid) return;
    pthread_mutex_lock(&b_finish_lock);
    if (atomic_exchange(&BS->finished, 1)) { pthread_mutex_unlock(&b_finish_lock); return; }
    if (b_before_finish) b_before_finish();
    int64_t end = b_mono();
    char path[4096];
    FILE *f = b_open_key("BENCH_KEY_FD", "ground_truth.json", path, sizeof path);
    if (!f) { perror(path); pthread_mutex_unlock(&b_finish_lock); return; }
    fprintf(f, "{\n  \"program\": ");
    b_json_str(f, B.prog->name);
    fprintf(f, ",\n  \"program_description\": ");
    b_json_str(f, B.prog->description);
    fprintf(f, ",\n  \"fault\": ");
    b_json_str(f, B.fault->name);
    fprintf(f, ",\n  \"fault_summary\": ");
    b_json_str(f, B.fault->summary);
    fprintf(f, ",\n  \"present\": ");
    b_json_ids(f, B.fault->present);
    fprintf(f, ",\n  \"dont_care\": ");
    b_json_ids(f, B.fault->dont_care);
    fprintf(f, ",\n  \"command\": \"");
    for (int i = 0; i < B.argc; i++) fprintf(f, "%s%s", i ? " " : "", B.argv[i]);
    fprintf(f, "\",\n  \"pid\": %d,\n  \"duration_s\": %.3f,\n  \"elapsed_s\": %.3f,\n",
            B.main_pid, B.duration_s, b_rel(end));
    fprintf(f, "  \"clock\": {\"start_monotonic_ns\": %lld, \"start_realtime_ns\": %lld, "
               "\"end_monotonic_ns\": %lld},\n",
            (long long)B.start_mono, (long long)B.start_real, (long long)end);
    fprintf(f, "  \"cpu\": %d,\n  \"seed\": %u,\n", B.cpu, B.seed);
    fprintf(f, "  \"metrics\": {");
    int nm = atomic_load(&BS->nmetrics);
    if (nm > B_MAX_METRICS) nm = B_MAX_METRICS;
    for (int i = 0; i < nm; i++) {
        fprintf(f, "%s\n    ", i ? "," : "");
        b_json_str(f, BS->metrics[i].key);
        fprintf(f, ": %.10g", BS->metrics[i].value);
    }
    fprintf(f, "\n  },\n  \"threads\": [");
    int nt = atomic_load(&BS->nthreads);
    if (nt > B_MAX_THREADS) nt = B_MAX_THREADS;
    for (int i = 0; i < nt; i++) {
        struct b_thread *t = &BS->threads[i];
        fprintf(f, "%s\n    {\"name\": ", i ? "," : "");
        b_json_str(f, t->name);
        fprintf(f, ", \"pid\": %d, \"tid\": %d, \"role\": ", t->pid, t->tid);
        b_json_str(f, t->role);
        fputc('}', f);
    }
    fprintf(f, "\n  ],\n  \"intervals\": [");
    int ni = atomic_load(&BS->nintervals);
    if (ni > B_MAX_INTERVALS) ni = B_MAX_INTERVALS;
    for (int i = 0; i < ni; i++) {
        struct b_interval *v = &BS->intervals[i];
        fprintf(f, "%s\n    {\"kind\": ", i ? "," : "");
        b_json_str(f, v->kind);
        fprintf(f, ", \"thread\": ");
        b_json_str(f, v->thread);
        fprintf(f, ", \"tid\": %d, \"start_s\": %.6f, \"end_s\": %.6f, \"duration_ms\": %.3f, "
                   "\"start_monotonic_ns\": %lld, \"end_monotonic_ns\": %lld, \"note\": ",
                v->tid, b_rel(v->start), b_rel(v->end), (double)(v->end - v->start) / 1e6,
                (long long)v->start, (long long)v->end);
        b_json_str(f, v->note);
        fputc('}', f);
    }
    fprintf(f, "\n  ],\n  \"intervals_dropped\": %d\n}\n",
            atomic_load(&BS->nintervals) > B_MAX_INTERVALS
                ? atomic_load(&BS->nintervals) - B_MAX_INTERVALS : 0);
    fclose(f);

    pthread_mutex_lock(&b_rows_lock);
    if (b_nrows || getenv("BENCH_SERIES_FD")) {
        FILE *s = b_open_key("BENCH_SERIES_FD", "series.csv", path, sizeof path);
        if (s) {
            fprintf(s, "series,thread,tid,t_s,value\n");
            for (size_t i = 0; i < b_nrows; i++)
                fprintf(s, "%s,%s,%d,%.6f,%.6g\n", b_rows[i].series, b_rows[i].thread,
                        b_rows[i].tid, b_rel(b_rows[i].t), b_rows[i].value);
            fclose(s);
        }
    }
    pthread_mutex_unlock(&b_rows_lock);
    printf("[%s] answer key written to %s\n", B.prog->name, B.out_dir);
    fflush(stdout);
    pthread_mutex_unlock(&b_finish_lock);
}

/* ---------------------------------------------------------------- watchdog */

static double b_watchdog_grace_s = 10.0;

/*
 * Under capture.sh, asks it to stop tracing and waits until it has, so a stuck run's trace ends
 * with its threads still blocked, as a real hung program's would. Without this, the watchdog's
 * _exit() would wake every blocked thread inside the trace, and the critical path would name
 * the watchdog as what they were all waiting for. capture.sh passes two FIFOs: the watchdog
 * writes a byte to the first, and capture.sh writes to the second once `lttng stop` returns.
 */
static void b_stop_tracing_first(void) {
    const char *req = getenv("BENCH_TRACE_STOP_FIFO"), *ack = getenv("BENCH_TRACE_STOPPED_FIFO");
    if (!req || !ack) return;
    int fd = open(req, O_WRONLY | O_NONBLOCK); /* fails at once if capture.sh is not listening */
    if (fd < 0) return;
    if (write(fd, "s", 1) < 0) {}
    close(fd);
    alarm(30); /* if capture.sh never answers, SIGALRM ends the run anyway */
    fd = open(ack, O_RDONLY);
    if (fd >= 0) {
        char c;
        if (read(fd, &c, 1) < 0) {}
        close(fd);
    }
    alarm(0);
}

/*
 * Ends the run `grace` seconds after the duration if the program has not ended itself: the
 * faults that leave threads stuck for good (deadlock, hang, never exits) rely on it.
 */
static void *b_watchdog_main(void *arg) {
    (void)arg;
    b_thread_start("watchdog", "ends the run if the program does not end itself");
    b_sleep_until(B.end_mono + (int64_t)(b_watchdog_grace_s * 1e9));
    if (atomic_load(&BS->finished)) return NULL;
    b_stop_tracing_first();
    b_metric("ended_by_watchdog", 1);
    printf("[%s] still running %.1f s after the end of the run: exiting\n", B.prog->name,
           b_watchdog_grace_s);
    fflush(stdout);
    b_finish();
    _exit(0);
}

static void b_on_signal(int sig) { (void)sig; b_stop_requested = 1; }

/* ---------------------------------------------------------------- options */

static double b_parse_duration(const char *s) {
    char *end;
    double v = strtod(s, &end);
    if (end == s || v <= 0) return -1;
    if (*end == 0 || strcmp(end, "s") == 0) return v;
    if (strcmp(end, "ms") == 0) return v / 1000;
    if (strcmp(end, "m") == 0) return v * 60;
    if (strcmp(end, "h") == 0) return v * 3600;
    return -1;
}

static int b_has(const char *csv, const char *id) {
    size_t n = strlen(id);
    for (const char *p = csv; p && *p;) {
        while (*p == ' ') p++;
        if (strncmp(p, id, n) == 0 && (p[n] == ',' || p[n] == 0)) return 1;
        p = strchr(p, ',');
        if (p) p++;
    }
    return 0;
}

static void b_list_faults(const bench_program *prog) {
    printf("{\"program\": ");
    b_json_str(stdout, prog->name);
    printf(", \"description\": ");
    b_json_str(stdout, prog->description);
    printf(", \"faults\": [");
    for (int i = -1; i < prog->nfaults; i++) {
        const bench_fault *x = i < 0 ? &b_fault_none : &prog->faults[i];
        printf("%s\n  {\"name\": ", i < 0 ? "" : ",");
        b_json_str(stdout, x->name);
        printf(", \"summary\": ");
        b_json_str(stdout, x->summary);
        printf(", \"present\": ");
        b_json_ids(stdout, x->present);
        printf(", \"dont_care\": ");
        b_json_ids(stdout, x->dont_care);
        putchar('}');
    }
    printf("\n]}\n");
}

static void b_usage(const bench_program *prog) {
    printf("usage: %s [--fault NAME] [-d DURATION] [-o DIR] [--data DIR] [--cpu N] [--seed N]\n"
           "       %s --list-faults\n\n%s\n\nfaults: none",
           prog->name, prog->name, prog->description);
    for (int i = 0; i < prog->nfaults; i++) printf(", %s", prog->faults[i].name);
    printf("\n\n  -d DURATION  run length: 30, 30s, 2m, ... (default 30s)\n"
           "  -o DIR       where to write the answer key (default ./ground_truth)\n"
           "  --data DIR   scratch files for programs that write files (default ./data)\n"
           "  --cpu N      first CPU the program pins to (default 3)\n");
}

/* Parse the common options, set up the answer key and start the watchdog. */
static void b_init(int argc, char **argv, const bench_program *prog, int default_cpu) {
    memset(&B, 0, sizeof B);
    B.prog = prog;
    B.fault = &b_fault_none;
    B.duration_s = 30;
    B.out_dir = "ground_truth";
    B.data_dir = "data";
    B.cpu = default_cpu;
    B.seed = 1;
    B.argc = argc;
    B.argv = argv;
    static const struct option opts[] = {
        { "fault", required_argument, 0, 'f' }, { "duration", required_argument, 0, 'd' },
        { "out", required_argument, 0, 'o' },   { "data", required_argument, 0, 'D' },
        { "cpu", required_argument, 0, 'c' },   { "seed", required_argument, 0, 's' },
        { "list-faults", no_argument, 0, 'l' }, { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 },
    };
    const char *fault = "none";
    int c;
    while ((c = getopt_long(argc, argv, "f:d:o:h", opts, NULL)) != -1) {
        switch (c) {
        case 'f': fault = optarg; break;
        case 'd':
            B.duration_s = b_parse_duration(optarg);
            if (B.duration_s <= 0) { fprintf(stderr, "bad duration: %s\n", optarg); exit(2); }
            break;
        case 'o': B.out_dir = optarg; break;
        case 'D': B.data_dir = optarg; break;
        case 'c': B.cpu = atoi(optarg); break;
        case 's': B.seed = (unsigned)strtoul(optarg, NULL, 10); break;
        case 'l': b_list_faults(prog); exit(0);
        case 'h': b_usage(prog); exit(0);
        default: b_usage(prog); exit(2);
        }
    }
    if (strcmp(fault, "none") != 0) {
        B.fault = NULL;
        for (int i = 0; i < prog->nfaults; i++)
            if (strcmp(prog->faults[i].name, fault) == 0) B.fault = &prog->faults[i];
        if (!B.fault) { fprintf(stderr, "unknown fault: %s\n", fault); b_usage(prog); exit(2); }
    }
    BS = mmap(NULL, sizeof *BS, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (BS == MAP_FAILED) { perror("mmap"); exit(1); }
    memset(BS, 0, sizeof *BS);
    if (!getenv("BENCH_KEY_FD")) b_mkdirs(B.out_dir); /* capture.sh made it before tracing */
    srand(B.seed);
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, b_on_signal);
    signal(SIGTERM, b_on_signal);
    signal(SIGPIPE, SIG_IGN);
    B.main_pid = getpid();
    b_thread_start(prog->name, "main thread");
    b_calibrate();
    B.start_real = b_real();
    B.start_mono = b_mono();
    B.end_mono = B.start_mono + (int64_t)(B.duration_s * 1e9);
    b_metric("cpu_work_iterations_per_ms", B.iters_per_ms);
    printf("[%s] fault=%s duration=%.1fs pid=%d\n", prog->name, B.fault->name, B.duration_s,
           B.main_pid);
    pthread_t wd;
    pthread_create(&wd, NULL, b_watchdog_main, NULL);
    pthread_detach(wd);
}

static int b_fault_is(const char *name) { return strcmp(B.fault->name, name) == 0; }

/* Start a thread running fn(arg). */
static pthread_t b_spawn(void *(*fn)(void *), void *arg) {
    pthread_t t;
    if (pthread_create(&t, NULL, fn, arg) != 0) { perror("pthread_create"); exit(1); }
    return t;
}

/* Simple statistics over an array, for the metrics. */
static double b_mean(const double *v, int n) {
    double s = 0;
    for (int i = 0; i < n; i++) s += v[i];
    return n ? s / n : 0;
}

static int b_cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* The q-th quantile (0..1) of v[0..n); sorts a copy. */
static double b_quantile(const double *v, int n, double q) {
    if (n <= 0) return 0;
    double *c = malloc((size_t)n * sizeof *c);
    memcpy(c, v, (size_t)n * sizeof *c);
    qsort(c, (size_t)n, sizeof *c, b_cmp_double);
    double r = c[(int)(q * (n - 1) + 0.5)];
    free(c);
    return r;
}

#endif
