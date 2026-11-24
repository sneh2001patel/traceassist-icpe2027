/*
 * cachesvc: an in-memory cache. At start it allocates and fills a 256 MB arena; a loader
 * refreshes part of it every 200 ms, and two server threads do 50 random lookups in it every
 * 1 ms. New workload, for the memory symptoms.
 *
 * memory_pressure makes the loader throw the arena's pages away (madvise MADV_DONTNEED) and
 * touch them all again every 200 ms: ~65,000 page faults per cycle. This kernel's LTTng has
 * no page-fault or kmem probe, so on this machine the faults themselves are not in the trace
 * (symptoms.json marks memory_pressure as needing "mem" events).
 *
 * Build: make cachesvc        Run: ./cachesvc --fault allocation_churn -d 30s -o gt/
 */
#include "bench.h"
#include <malloc.h>

#define ARENA (256UL << 20)
#define PAGE 4096UL

static const bench_fault faults[] = {
    { "memory_pressure",
      "every 200 ms the loader discards the whole 256 MB arena (madvise MADV_DONTNEED) and "
      "touches every page again, four times over: ~260,000 page faults per cycle, keeping the "
      "loader busy about a quarter of the time, almost all of it in the kernel handling them",
      "memory_pressure", "cpu_hog" },
    { "allocation_churn",
      "for every lookup batch the servers allocate a 256 KB buffer, fill it and free it; each "
      "allocation is an mmap() and each free an munmap() (~1000 of each per second per server)",
      "allocation_churn", "memory_pressure,many_small_calls" },
};
static const bench_program program = {
    "cachesvc",
    "an in-memory cache: a 256 MB arena filled at start, a loader that refreshes part of it "
    "every 200 ms, and two server threads doing lookups every 1 ms",
    faults, sizeof faults / sizeof faults[0],
};

static unsigned char *arena;
static atomic_long lookups, allocations;

#define MAX_CYCLES 100000
static double cycle_ms[MAX_CYCLES];
static int ncycles;

static void record_metrics(void) {
    int n = ncycles < MAX_CYCLES ? ncycles : MAX_CYCLES;
    b_metric("lookups", (double)atomic_load(&lookups));
    b_metric("allocations", (double)atomic_load(&allocations));
    b_metric("loader_cycles", ncycles);
    b_metric("loader_cycle_ms_mean", b_mean(cycle_ms, n));
    b_metric("loader_cycle_ms_max", b_quantile(cycle_ms, n, 1.0));
}

static void touch_all(unsigned char v) {
    for (unsigned long i = 0; i < ARENA; i += PAGE) arena[i] = v;
}

static void *loader_main(void *arg) {
    (void)arg;
    b_thread_start("loader", "refreshes the cache every 200 ms");
    b_pin(B.cpu);
    int64_t next = b_mono();
    unsigned char v = 1;
    while (b_running()) {
        next += 200000000;
        b_sleep_until(next);
        int64_t t0 = b_mono();
        if (b_fault_is("memory_pressure")) {
            for (int k = 0; k < 4; k++) {
                madvise(arena, ARENA, MADV_DONTNEED);
                touch_all(v++);
            }
        } else {
            for (unsigned long i = 0; i < ARENA / 64; i += PAGE) arena[i] = v; /* 1/64 of it */
            v++;
            b_burn_ms(1);
        }
        int64_t t1 = b_mono();
        double ms = (double)(t1 - t0) / 1e6;
        if (ncycles < MAX_CYCLES) cycle_ms[ncycles] = ms;
        ncycles++;
        b_series("loader_cycle_ms", t0, ms);
        if (b_fault_is("memory_pressure"))
            b_interval("page_faults", t0, t1, "re-touched %lu discarded pages", 4 * (ARENA / PAGE));
    }
    return NULL;
}

static void *server_main(void *arg) {
    int id = (int)(intptr_t)arg;
    char name[16];
    snprintf(name, sizeof name, "server-%d", id);
    b_thread_start(name, "serves lookups");
    b_pin(B.cpu + 1 + id);
    unsigned seed = B.seed + (unsigned)id;
    int64_t next = b_mono();
    unsigned long sum = 0;
    while (b_running()) {
        next += 1000000;
        b_sleep_until(next);
        unsigned char *scratch = NULL;
        if (b_fault_is("allocation_churn")) {
            scratch = malloc(256 << 10);
            memset(scratch, 0, 256 << 10);
            atomic_fetch_add(&allocations, 1);
        }
        for (int k = 0; k < 50; k++) sum += arena[(rand_r(&seed) % (ARENA / 64)) * 64];
        if (scratch) { scratch[0] = (unsigned char)sum; free(scratch); }
        atomic_fetch_add(&lookups, 50);
        if (b_mono() > next + 10000000) next = b_mono();
    }
    b_sink += sum;
    return NULL;
}

int main(int argc, char **argv) {
    b_init(argc, argv, &program, 3);
    b_before_finish = record_metrics;
    mallopt(M_MMAP_THRESHOLD, 128 * 1024); /* fixed: keeps 256 KB allocations on mmap */
    arena = mmap(NULL, ARENA, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) { perror("mmap"); return 1; }
    int64_t t0 = b_mono();
    touch_all(0);
    b_interval("arena_fill", t0, b_mono(), "fills the 256 MB arena once at start");
    pthread_t l = b_spawn(loader_main, NULL);
    pthread_t s0 = b_spawn(server_main, (void *)(intptr_t)0);
    pthread_t s1 = b_spawn(server_main, (void *)(intptr_t)1);
    pthread_join(l, NULL);
    pthread_join(s0, NULL);
    pthread_join(s1, NULL);
    munmap(arena, ARENA);
    printf("[cachesvc] %ld lookups, %ld allocations\n", atomic_load(&lookups),
           atomic_load(&allocations));
    b_finish();
    return 0;
}
