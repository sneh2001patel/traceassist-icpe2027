/*
 * pipeline: reader -> parser -> 4 sinks, joined by bounded queues (64 items, mutex + condition
 * variables). The reader produces an item every 0.5 ms (2000 per second), the parser spends
 * 0.2 ms on each, and hands them round-robin to sink-0..3 (one queue each), which spend
 * 0.4 ms on each. The pipeline_demo workload (lttng_critical_path_demo/), rebuilt with a fault
 * switch for the pipeline symptoms.
 *
 * The coordinator samples every queue's depth every 10 ms (queue_depth series); the sinks
 * record every 10th item's end-to-end latency (item_latency_ms).
 *
 * Build: make pipeline        Run: ./pipeline --fault slow_stage -d 30s -o gt/
 */
#include "bench.h"

#define QCAP 64
#define MAX_SINKS 16

static const bench_fault faults[] = {
    { "slow_stage",
      "the parser spends 1.5 ms per item instead of 0.2 ms, below the reader's 2000 items per "
      "second: its input queue stays full, the reader blocks on it and the sinks starve",
      "slowest_stage,bottleneck_thread",
      "producer_consumer_mismatch,long_blocked_waits,idle_workers" },
    { "bursty",
      "the reader produces in bursts, 500 items as fast as it can, then nothing for 400 ms: "
      "the queues fill up during a burst and drain empty between bursts",
      "producer_consumer_mismatch", "slowest_stage,idle_workers,long_blocked_waits" },
    { "herd",
      "16 sink threads (instead of 4) share one queue, and the parser wakes all of them "
      "(pthread_cond_broadcast) for every item: each item wakes 16 threads and only one gets it",
      "thundering_herd", "scheduling_delay,lock_contention,many_small_calls" },
    { "idle_workers",
      "the parser hands every item to sink-0 instead of round-robin: sink-0 is busy ~80% of the "
      "time and sink-1..3 never get any work",
      "idle_workers,load_imbalance", "bottleneck_thread,slowest_stage,thread_differences,idle_thread" },
    { "idle_thread",
      "an extra compressor thread is started at launch and waits forever for work that never "
      "comes; the pipeline itself is healthy",
      "idle_thread", "" },
};
static const bench_program program = {
    "pipeline",
    "reader -> parser -> 4 sinks joined by bounded queues; 2000 items per second",
    faults, sizeof faults / sizeof faults[0],
};

struct queue {
    pthread_mutex_t lock;
    pthread_cond_t not_empty, not_full;
    int64_t items[QCAP];
    int head, count, closed;
};

static void q_init(struct queue *q) {
    memset(q, 0, sizeof *q);
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

static void q_put(struct queue *q, int64_t v, int broadcast) {
    pthread_mutex_lock(&q->lock);
    while (q->count == QCAP && !q->closed) pthread_cond_wait(&q->not_full, &q->lock);
    q->items[(q->head + q->count) % QCAP] = v;
    q->count++;
    if (broadcast) pthread_cond_broadcast(&q->not_empty);
    else pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

/* 0 when the queue is closed and empty. */
static int q_get(struct queue *q, int64_t *v) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !q->closed) pthread_cond_wait(&q->not_empty, &q->lock);
    if (q->count == 0) { pthread_mutex_unlock(&q->lock); return 0; }
    *v = q->items[q->head];
    q->head = (q->head + 1) % QCAP;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return 1;
}

static void q_close(struct queue *q) {
    pthread_mutex_lock(&q->lock);
    q->closed = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->lock);
}

static int q_depth(struct queue *q) {
    pthread_mutex_lock(&q->lock);
    int n = q->count;
    pthread_mutex_unlock(&q->lock);
    return n;
}

static struct queue parse_q, sink_q[MAX_SINKS], shared_q;
static int nsinks = 4;
static atomic_long produced, parsed, sunk[MAX_SINKS];

static void record_metrics(void) {
    b_metric("items_produced", (double)atomic_load(&produced));
    b_metric("items_parsed", (double)atomic_load(&parsed));
    for (int i = 0; i < nsinks; i++) {
        char key[32];
        snprintf(key, sizeof key, "items_sink-%d", i);
        b_metric(key, (double)atomic_load(&sunk[i]));
    }
}

static void *reader_main(void *arg) {
    (void)arg;
    b_thread_start("reader", "stage 1: produces items");
    b_pin(B.cpu);
    int64_t next = b_mono();
    long n = 0;
    while (b_running()) {
        if (b_fault_is("bursty")) {
            int64_t t0 = b_mono();
            for (int k = 0; k < 500 && b_running(); k++, n++) q_put(&parse_q, b_mono(), 0);
            b_interval("burst", t0, b_mono(), "500 items as fast as the queue takes them");
            b_sleep_ms(400);
        } else {
            next += 500000;
            b_sleep_until(next);
            q_put(&parse_q, b_mono(), 0);
            n++;
        }
        atomic_store(&produced, n);
    }
    q_close(&parse_q);
    return NULL;
}

static void *parser_main(void *arg) {
    (void)arg;
    b_thread_start("parser", "stage 2: parses items, hands them to the sinks");
    b_pin(B.cpu + 1);
    double work = b_fault_is("slow_stage") ? 1.5 : 0.2;
    int64_t v;
    long n = 0;
    while (q_get(&parse_q, &v)) {
        b_burn_ms(work);
        if (b_fault_is("herd")) q_put(&shared_q, v, 1);
        else if (b_fault_is("idle_workers")) q_put(&sink_q[0], v, 0);
        else q_put(&sink_q[n % nsinks], v, 0);
        n++;
        atomic_store(&parsed, n);
    }
    if (b_fault_is("herd")) q_close(&shared_q);
    for (int i = 0; i < nsinks; i++) q_close(&sink_q[i]);
    return NULL;
}

static void *sink_main(void *arg) {
    int id = (int)(intptr_t)arg;
    char name[16];
    snprintf(name, sizeof name, "sink-%d", id);
    b_thread_start(name, "stage 3: stores items");
    if (b_fault_is("herd")) b_pin_range(B.cpu + 2, 4);
    else b_pin(B.cpu + 2 + id);
    struct queue *q = b_fault_is("herd") ? &shared_q : &sink_q[id];
    int64_t v;
    long n = 0;
    while (q_get(q, &v)) {
        b_burn_ms(0.4);
        if (n % 10 == 0) b_series("item_latency_ms", v, (double)(b_mono() - v) / 1e6);
        n++;
        atomic_store(&sunk[id], n);
    }
    return NULL;
}

static pthread_mutex_t never_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t never_cond = PTHREAD_COND_INITIALIZER;
static int never_flag;

static void *compressor_main(void *arg) {
    (void)arg;
    b_thread_start("compressor", "compresses finished batches");
    b_interval("idle_forever", b_mono(), B.end_mono, "waits for work that never comes");
    pthread_mutex_lock(&never_lock);
    while (!never_flag) pthread_cond_wait(&never_cond, &never_lock);
    pthread_mutex_unlock(&never_lock);
    return NULL;
}

int main(int argc, char **argv) {
    b_init(argc, argv, &program, 3);
    b_before_finish = record_metrics;
    if (b_fault_is("herd")) nsinks = 16;
    q_init(&parse_q);
    q_init(&shared_q);
    for (int i = 0; i < MAX_SINKS; i++) q_init(&sink_q[i]);
    pthread_t sinks[MAX_SINKS], compressor = 0;
    for (int i = 0; i < nsinks; i++) sinks[i] = b_spawn(sink_main, (void *)(intptr_t)i);
    if (b_fault_is("idle_thread")) compressor = b_spawn(compressor_main, NULL);
    pthread_t p = b_spawn(parser_main, NULL);
    pthread_t r = b_spawn(reader_main, NULL);
    while (b_running()) {
        b_sleep_ms(10);
        int64_t t = b_mono();
        b_series("parse_queue_depth", t, q_depth(&parse_q));
        if (b_fault_is("herd")) b_series("sink_queue_depth", t, q_depth(&shared_q));
        else b_series("sink-0_queue_depth", t, q_depth(&sink_q[0]));
    }
    pthread_join(r, NULL);
    pthread_join(p, NULL);
    for (int i = 0; i < nsinks; i++) pthread_join(sinks[i], NULL);
    if (compressor) {
        pthread_mutex_lock(&never_lock);
        never_flag = 1; /* only at exit, after the run */
        pthread_cond_signal(&never_cond);
        pthread_mutex_unlock(&never_lock);
        pthread_join(compressor, NULL);
    }
    printf("[pipeline] produced %ld, parsed %ld\n", atomic_load(&produced), atomic_load(&parsed));
    b_finish();
    return 0;
}
