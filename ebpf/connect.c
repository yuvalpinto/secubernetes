// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <bpf/libbpf.h>
#include "connect.skel.h"

static volatile sig_atomic_t stop;

struct connect_event {
    __u32 pid;
    __u32 uid;
    __u64 cgroup_id;

    int fd;
    int addrlen;
    __u16 family;
    __u16 port;
    __u32 ipv4_addr;
    __u8 ipv6_addr[16];
    char comm[16];

    int ret;
    __u8 success;
};

static void handle_sigint(int sig)
{
    stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "[perf-buffer] lost %llu events on cpu %d\n", lost_cnt, cpu);
}

static int is_ignored_comm(const char *comm)
{
    const char *ignored[] = {
        "node",
        "grep",
        "ps",
        "less",
        "dircolors",
        "locale",
        "locale-check"
    };

    size_t count = sizeof(ignored) / sizeof(ignored[0]);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(comm, ignored[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static void print_json_escaped(const char *s)
{
    for (; *s; s++) {
        switch (*s) {
            case '\\': fputs("\\\\", stdout); break;
            case '"':  fputs("\\\"", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:   fputc(*s, stdout); break;
        }
    }
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct connect_event *e = data;

    char comm[17];
    char ip_str[INET6_ADDRSTRLEN] = "";

    memcpy(comm, e->comm, sizeof(e->comm));
    comm[16] = '\0';

    if (is_ignored_comm(comm)) {
        return;
    }

    if (e->family != AF_INET && e->family != AF_INET6) {
        return;
    }

    printf("{\"pid\":%u,\"uid\":%u,\"cgroup_id\":%llu,\"fd\":%d,\"addrlen\":%d,\"family\":%u,\"comm\":\"",
       e->pid, e->uid, (unsigned long long)e->cgroup_id, e->fd, e->addrlen, e->family);
    print_json_escaped(comm);
    printf("\"");

    if (e->family == AF_INET) {
        struct in_addr addr4;
        addr4.s_addr = e->ipv4_addr;

        if (inet_ntop(AF_INET, &addr4, ip_str, sizeof(ip_str))) {
            printf(",\"ip\":\"%s\",\"port\":%u,\"ip_version\":4",
                   ip_str, ntohs(e->port));
        }
    } else if (e->family == AF_INET6) {
        struct in6_addr addr6;
        memcpy(&addr6, e->ipv6_addr, 16);

        if (inet_ntop(AF_INET6, &addr6, ip_str, sizeof(ip_str))) {
            printf(",\"ip\":\"%s\",\"port\":%u,\"ip_version\":6",
                   ip_str, ntohs(e->port));
        }
    }

    printf(",\"ret\":%d,\"success\":%s", e->ret, e->success ? "true" : "false");
    printf("}\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct connect_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    struct perf_buffer_opts pb_opts = {};
    int err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    skel = connect_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = connect_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = connect_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    pb_opts.sample_cb = handle_event;
    pb_opts.lost_cb = handle_lost_events;

    pb = perf_buffer__new(
        bpf_map__fd(skel->maps.events),
        64,
        &pb_opts
    );
    if (!pb) {
        err = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    fprintf(stderr, "Listening for connect exit events... Press Ctrl+C to stop.\n");

    while (!stop) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
        err = 0;
    }

cleanup:
    perf_buffer__free(pb);
    connect_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}