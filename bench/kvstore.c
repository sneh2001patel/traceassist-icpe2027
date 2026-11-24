/*
 * kvstore: four client threads (client-0..3) each send a request every 5 ms, over loopback
 * TCP, to a key-value server running as a separate process (kvd, forked at start, one thread
 * per connection, pinned to one CPU), and wait for the reply. The server spends 0.1 ms per
 * request. New workload, for waiting on another process, tail latency and waiting on the
 * network.
 *
 * The clients record every request's latency (request_ms).
 *
 * network_wait connects to 10.255.255.1, an address that is routed out of the machine but
 * never answers, so every attempt waits for its full timeout. It needs a default route.
 *
 * Build: make kvstore        Run: ./kvstore --fault slow_backend -d 30s -o gt/
 */
#include "bench.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define CLIENTS 4
#define REQ 32
#define RESP 256

static const bench_fault faults[] = {
    { "slow_backend",
      "the server (process kvd) spends 3 ms per request instead of 0.1 ms, all on one CPU: "
      "the server is saturated and the clients spend most of their time blocked waiting for "
      "its replies",
      "waiting_on_process,bottleneck_thread", "tail_latency,cpu_hog,long_blocked_waits" },
    { "tail_latency",
      "2% of requests, chosen at random, take 25 ms on the server (a slow path that waits) "
      "instead of 0.1 ms; the other 98% are as fast as in the healthy run",
      "tail_latency", "waiting_on_process,jitter,one_off_delay" },
    { "network_wait",
      "once a second each client tries to reach a replica at 10.255.255.1:7070, which never "
      "answers, and waits 300 ms for the connection before giving up: the clients are blocked "
      "on the network ~30% of the time",
      "waiting_on_network,long_blocked_waits", "failing_retry_loop,tail_latency" },
};
static const bench_program program = {
    "kvstore",
    "4 client threads each send a request every 5 ms over loopback TCP to a key-value server "
    "process (kvd) and wait for the reply",
    faults, sizeof faults / sizeof faults[0],
};

static int listen_fd, server_pid;
static atomic_long requests, net_attempts;

#define MAX_REQ 400000
static double *req_ms;
static atomic_int nreq;

static void record_metrics(void) {
    int n = atomic_load(&nreq);
    if (n > MAX_REQ) n = MAX_REQ;
    b_metric("requests", (double)atomic_load(&requests));
    b_metric("request_ms_mean", b_mean(req_ms, n));
    b_metric("request_ms_p50", b_quantile(req_ms, n, 0.5));
    b_metric("request_ms_p99", b_quantile(req_ms, n, 0.99));
    b_metric("request_ms_max", b_quantile(req_ms, n, 1.0));
    b_metric("replica_connect_attempts", (double)atomic_load(&net_attempts));
}

static int full_io(int fd, char *buf, size_t n, int sending) {
    size_t done = 0;
    while (done < n) {
        ssize_t k = sending ? send(fd, buf + done, n - done, 0) : recv(fd, buf + done, n - done, 0);
        if (k <= 0) return -1;
        done += (size_t)k;
    }
    return 0;
}

/* ---- server process ---- */

static void *conn_main(void *arg) {
    int fd = (int)(intptr_t)arg;
    static atomic_int next_id;
    char name[16];
    snprintf(name, sizeof name, "kvd-conn-%d", atomic_fetch_add(&next_id, 1));
    b_thread_start(name, "server: serves one client connection");
    b_pin(B.cpu + 4);
    unsigned seed = (unsigned)fd * 7919u + B.seed;
    char req[REQ], resp[RESP];
    memset(resp, 'v', sizeof resp);
    while (full_io(fd, req, REQ, 0) == 0) {
        if (b_fault_is("slow_backend")) {
            b_burn_ms(3);
        } else if (b_fault_is("tail_latency") && rand_r(&seed) % 100 < 2) {
            int64_t t0 = b_mono();
            b_burn_ms(0.1);
            b_sleep_ms(25);
            b_interval("slow_request", t0, b_mono(), "request took the 25 ms slow path");
        } else {
            b_burn_ms(0.1);
        }
        if (full_io(fd, resp, RESP, 1) != 0) break;
    }
    close(fd);
    return NULL;
}

static void server_process(void) {
    signal(SIGTERM, SIG_DFL); /* the client process stops it at the end */
    prctl(PR_SET_NAME, "kvd", 0, 0, 0);
    b_thread_start("kvd", "server process: accepts connections");
    b_pin(B.cpu + 4);
    for (int i = 0; i < CLIENTS; i++) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) _exit(1);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        pthread_t t = b_spawn(conn_main, (void *)(intptr_t)fd);
        pthread_detach(t);
    }
    for (;;) pause(); /* killed by the client process at the end */
}

/* ---- client process ---- */

static void replica_check(void) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s < 0) return;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(7070) };
    inet_pton(AF_INET, "10.255.255.1", &a.sin_addr);
    int64_t t0 = b_mono();
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    const char *result = "connected";
    if (r != 0 && errno == EINPROGRESS) {
        struct pollfd p = { s, POLLOUT, 0 };
        result = poll(&p, 1, 300) == 0 ? "no answer after 300 ms" : "failed";
    } else if (r != 0) {
        result = strerror(errno);
    }
    close(s);
    atomic_fetch_add(&net_attempts, 1);
    b_interval("network_wait", t0, b_mono(), "connect to replica 10.255.255.1:7070: %s", result);
}

static void *client_main(void *arg) {
    int id = (int)(intptr_t)arg;
    char name[16];
    snprintf(name, sizeof name, "client-%d", id);
    b_thread_start(name, "client: sends a request every 5 ms");
    b_pin(B.cpu + id);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    getsockname(listen_fd, (struct sockaddr *)&a, &len);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { perror("connect"); return NULL; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    char req[REQ], resp[RESP];
    memset(req, 'k', sizeof req);
    int64_t period = 5000000, next = b_mono() + period;
    int64_t next_check = b_mono() + 1000000000LL + id * 250000000LL;
    while (b_running()) {
        if (b_fault_is("network_wait") && b_mono() >= next_check) {
            replica_check();
            next_check += 1000000000LL;
            next = b_mono();
        }
        b_sleep_until(next);
        int64_t t0 = b_mono();
        if (full_io(fd, req, REQ, 1) != 0 || full_io(fd, resp, RESP, 0) != 0) break;
        double ms = (double)(b_mono() - t0) / 1e6;
        int i = atomic_fetch_add(&nreq, 1);
        if (i < MAX_REQ) req_ms[i] = ms;
        atomic_fetch_add(&requests, 1);
        b_series("request_ms", t0, ms);
        next += period;
        if (b_mono() > next) next = b_mono();
    }
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    b_init(argc, argv, &program, 3);
    b_before_finish = record_metrics;
    req_ms = calloc(MAX_REQ, sizeof *req_ms);
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = 0 };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(listen_fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(listen_fd, 16) != 0) {
        perror("bind/listen");
        return 1;
    }
    server_pid = fork();
    if (server_pid == 0) server_process();
    b_metric("server_pid", server_pid);
    pthread_t clients[CLIENTS];
    for (int i = 0; i < CLIENTS; i++) clients[i] = b_spawn(client_main, (void *)(intptr_t)i);
    for (int i = 0; i < CLIENTS; i++) pthread_join(clients[i], NULL);
    kill(server_pid, SIGTERM);
    waitpid(server_pid, NULL, 0);
    printf("[kvstore] %ld requests\n", atomic_load(&requests));
    b_finish();
    return 0;
}
