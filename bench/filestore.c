/*
 * filestore: a record store. A writer appends a 4 KB record every 5 ms to records.dat (in
 * --data DIR) and syncs it every 2 s; a reader reads a 64 KB chunk every 100 ms; a stats
 * thread checks the file once a second. The file_write_demo / slow_io_demo /
 * slow_request_demo workloads (lttng_critical_path_demo/), rebuilt with a fault switch for the
 * system call and I/O symptoms.
 *
 * --data must be on a real disk (not tmpfs) for disk_wait to wait on the disk.
 *
 * Build: make filestore        Run: ./filestore --fault disk_wait -d 30s -o gt/ --data DIR
 */
#include "bench.h"
#include <dirent.h>
#include <poll.h>

#define RECORD 4096
#define FILE_CAP (64L << 20)

static const bench_fault faults[] = {
    { "disk_wait",
      "the writer syncs every record: 1000 records per second, each written and then "
      "fdatasync()ed (~0.6 ms on the disk each), plus an 8 MB checkpoint synced once a second "
      "(several ms); the writer is blocked on the disk 35-50% of the time",
      "waiting_on_disk,slow_syscalls", "long_blocked_waits,bottleneck_thread" },
    { "small_calls",
      "every 100 ms the reader reads 5000 bytes one byte per read() call (~50,000 read calls "
      "per second) instead of one 64 KB read",
      "many_small_calls", "cpu_hog" },
    { "polling",
      "the stats thread calls poll() with a zero timeout on a pipe that never has data, then "
      "sleeps 200 us, over and over (~4000 polls per second, all returning nothing)",
      "idle_polling", "many_small_calls" },
    { "retry_loop",
      "the stats thread tries to open data/incoming/batch.ready every 1 ms; the file never "
      "exists, so every open() fails with ENOENT",
      "failing_retry_loop", "idle_polling,many_small_calls" },
    { "file_churn",
      "the writer writes each 4 KB record to a new file (create, write, close, rename) and "
      "deletes the file from 100 records earlier: ~200 files created and deleted per second",
      "file_churn", "many_small_calls" },
    { "unexpected_scan",
      "every 2 s the stats thread walks /usr/share/doc, opening and reading the start of up to "
      "300 files that have nothing to do with the store",
      "unexpected_activity", "many_small_calls,file_churn" },
};
static const bench_program program = {
    "filestore",
    "a record store: a writer appends a 4 KB record every 5 ms and syncs every 2 s, a reader "
    "reads 64 KB every 100 ms, and a stats thread checks the file once a second",
    faults, sizeof faults / sizeof faults[0],
};

static char records_path[4096];
static atomic_long records, reads, syscalls_made, failures, files_touched;

#define MAX_SYNCS 100000
static double sync_ms[MAX_SYNCS];
static int syncs;

static void record_metrics(void) {
    int n = syncs < MAX_SYNCS ? syncs : MAX_SYNCS;
    b_metric("records_written", (double)atomic_load(&records));
    b_metric("reads", (double)atomic_load(&reads));
    b_metric("fault_syscalls", (double)atomic_load(&syscalls_made));
    b_metric("failed_calls", (double)atomic_load(&failures));
    b_metric("files_touched", (double)atomic_load(&files_touched));
    b_metric("syncs", syncs);
    b_metric("sync_ms_mean", b_mean(sync_ms, n));
    b_metric("sync_ms_p50", b_quantile(sync_ms, n, 0.5));
    b_metric("sync_ms_max", b_quantile(sync_ms, n, 1.0));
}

static void timed_sync(int fd, const char *what) {
    int64_t t0 = b_mono();
    fdatasync(fd);
    int64_t t1 = b_mono();
    double ms = (double)(t1 - t0) / 1e6;
    if (syncs < MAX_SYNCS) sync_ms[syncs] = ms;
    syncs++;
    b_series("fdatasync_ms", t0, ms);
    if (ms >= 1.0) b_interval("disk_sync", t0, t1, "fdatasync() of %s took %.2f ms", what, ms);
}

static void churn_writer(void) {
    static char buf[RECORD];
    memset(buf, 'r', sizeof buf);
    long n = 0;
    int64_t next = b_mono(), t0 = next;
    while (b_running()) {
        char tmp[4200], dat[4200];
        snprintf(tmp, sizeof tmp, "%s/seg-%06ld.tmp", B.data_dir, n);
        snprintf(dat, sizeof dat, "%s/seg-%06ld.dat", B.data_dir, n);
        int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            if (write(fd, buf, sizeof buf) < 0) {}
            close(fd);
            rename(tmp, dat);
        }
        if (n >= 100) {
            snprintf(dat, sizeof dat, "%s/seg-%06ld.dat", B.data_dir, n - 100);
            unlink(dat);
        }
        n++;
        atomic_fetch_add(&records, 1);
        atomic_fetch_add(&files_touched, 1);
        next += 5000000;
        b_sleep_until(next);
    }
    b_interval("file_churn", t0, b_mono(), "%ld files created and deleted", n);
    for (long k = n - 100 < 0 ? 0 : n - 100; k < n; k++) {
        char dat[4200];
        snprintf(dat, sizeof dat, "%s/seg-%06ld.dat", B.data_dir, k);
        unlink(dat);
    }
}

static void *writer_main(void *arg) {
    (void)arg;
    b_thread_start("writer", "appends records");
    b_pin(B.cpu);
    if (b_fault_is("file_churn")) { churn_writer(); return NULL; }
    int fd = open(records_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror(records_path); return NULL; }
    if (b_fault_is("disk_wait")) {
        size_t big = 8u << 20;
        char *buf = malloc(big);
        memset(buf, 'r', big);
        int64_t next = b_mono(), next_checkpoint = next + 1000000000LL;
        while (b_running()) {
            if (lseek(fd, 0, SEEK_CUR) + (off_t)big > FILE_CAP) lseek(fd, 0, SEEK_SET);
            buf[0]++;
            if (write(fd, buf, RECORD) < 0) break;
            timed_sync(fd, "one 4 KB record");
            atomic_fetch_add(&records, 1);
            if (b_mono() >= next_checkpoint) {
                for (size_t i = 0; i < big; i += 4096) buf[i]++; /* new data */
                if (write(fd, buf, big) < 0) break;
                timed_sync(fd, "an 8 MB checkpoint");
                next_checkpoint += 1000000000LL;
            }
            next += 1000000;
            if (b_mono() < next) b_sleep_until(next);
            else next = b_mono();
        }
        free(buf);
        close(fd);
        return NULL;
    }
    static char rec[RECORD];
    memset(rec, 'r', sizeof rec);
    int64_t next = b_mono(), last_sync = next;
    while (b_running()) {
        if (lseek(fd, 0, SEEK_CUR) + RECORD > FILE_CAP) lseek(fd, 0, SEEK_SET);
        if (write(fd, rec, sizeof rec) < 0) break;
        atomic_fetch_add(&records, 1);
        if (b_mono() - last_sync >= 2000000000LL) { timed_sync(fd, "the last 2 s"); last_sync = b_mono(); }
        next += 5000000;
        b_sleep_until(next);
    }
    close(fd);
    return NULL;
}

static void *reader_main(void *arg) {
    (void)arg;
    b_thread_start("reader", "reads records back");
    b_pin(B.cpu + 1);
    b_sleep_ms(200);
    static char buf[65536];
    while (b_running()) {
        int fd = open(records_path, O_RDONLY);
        if (fd >= 0) {
            if (b_fault_is("small_calls")) {
                int64_t t0 = b_mono();
                int k;
                for (k = 0; k < 5000; k++)
                    if (read(fd, buf, 1) != 1) break;
                atomic_fetch_add(&syscalls_made, k);
                b_series("one_byte_reads", t0, k);
            } else {
                off_t size = lseek(fd, 0, SEEK_END);
                off_t at = size > (off_t)sizeof buf ? (rand() % (size - (off_t)sizeof buf)) & ~4095L : 0;
                if (pread(fd, buf, sizeof buf, at) < 0) {}
            }
            atomic_fetch_add(&reads, 1);
            close(fd);
        }
        b_sleep_ms(100);
    }
    return NULL;
}

static int scan_dir(const char *dir, int budget) {
    DIR *d = opendir(dir);
    if (!d) return budget;
    struct dirent *e;
    char path[4096], buf[256];
    while (budget > 0 && (e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (e->d_type == DT_DIR) {
            budget = scan_dir(path, budget);
        } else if (e->d_type == DT_REG) {
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                if (read(fd, buf, sizeof buf) < 0) {}
                close(fd);
                budget--;
                atomic_fetch_add(&files_touched, 1);
            }
        }
    }
    closedir(d);
    return budget;
}

static void *stats_main(void *arg) {
    (void)arg;
    b_thread_start("stats", "checks the store once a second");
    b_pin(B.cpu + 2);
    int64_t t0 = b_mono();
    if (b_fault_is("polling")) {
        int p[2];
        if (pipe(p) != 0) return NULL;
        struct pollfd pfd = { p[0], POLLIN, 0 };
        long n = 0;
        while (b_running()) {
            poll(&pfd, 1, 0);
            n++;
            b_sleep_ms(0.2);
        }
        atomic_fetch_add(&syscalls_made, n);
        b_interval("polling", t0, b_mono(), "%ld zero-timeout polls, none ready", n);
        return NULL;
    }
    if (b_fault_is("retry_loop")) {
        char path[4200];
        snprintf(path, sizeof path, "%s/incoming/batch.ready", B.data_dir);
        long n = 0;
        while (b_running()) {
            int fd = open(path, O_RDONLY);
            if (fd >= 0) close(fd);
            else atomic_fetch_add(&failures, 1);
            n++;
            b_sleep_ms(1);
        }
        b_interval("retry_loop", t0, b_mono(), "%ld open() calls on %s, all failed (ENOENT)", n,
                   path);
        return NULL;
    }
    while (b_running()) {
        struct stat st;
        stat(records_path, &st);
        b_burn_ms(0.2);
        if (b_fault_is("unexpected_scan")) {
            int64_t s0 = b_mono();
            int left = scan_dir("/usr/share/doc", 300);
            b_interval("unexpected_scan", s0, b_mono(), "read the start of %d files under "
                       "/usr/share/doc", 300 - left);
            b_sleep_ms(2000);
        } else {
            b_sleep_ms(1000);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    b_init(argc, argv, &program, 3);
    b_before_finish = record_metrics;
    b_mkdirs(B.data_dir);
    snprintf(records_path, sizeof records_path, "%s/records.dat", B.data_dir);
    { /* exists from the start, so the reader always has something to read */
        int fd = open(records_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        static char mb[1 << 20];
        memset(mb, 'r', sizeof mb);
        if (fd >= 0) { if (write(fd, mb, sizeof mb) < 0) {} close(fd); }
    }
    pthread_t w = b_spawn(writer_main, NULL);
    pthread_t r = b_spawn(reader_main, NULL);
    pthread_t s = b_spawn(stats_main, NULL);
    pthread_join(w, NULL);
    pthread_join(r, NULL);
    pthread_join(s, NULL);
    unlink(records_path);
    printf("[filestore] %ld records, %d syncs\n", atomic_load(&records), syncs);
    b_finish();
    return 0;
}
