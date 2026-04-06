#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

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

struct connect_enter_state {
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
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct connect_enter_state);
} connect_state_map SEC(".maps");

struct syscall_trace_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

struct syscall_trace_exit {
    unsigned long long unused;
    long id;
    long ret;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect_enter(struct syscall_trace_enter *ctx)
{
    struct connect_enter_state state = {};
    const void *uservaddr;
    __u16 family = 0;
    __u64 pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();

    state.pid = pid_tgid >> 32;
    state.uid = (__u32)bpf_get_current_uid_gid();
    state.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&state.comm, sizeof(state.comm));

    state.fd = (int)ctx->args[0];
    uservaddr = (const void *)ctx->args[1];
    state.addrlen = (int)ctx->args[2];

    if (!uservaddr) {
        bpf_map_update_elem(&connect_state_map, &pid_tgid, &state, BPF_ANY);
        return 0;
    }

    bpf_probe_read_user(&family, sizeof(family), uservaddr);
    state.family = family;

    if (family == AF_INET && state.addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in addr4 = {};
        bpf_probe_read_user(&addr4, sizeof(addr4), uservaddr);

        state.port = addr4.sin_port;
        state.ipv4_addr = addr4.sin_addr.s_addr;
    } else if (family == AF_INET6 && state.addrlen >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 addr6 = {};
        bpf_probe_read_user(&addr6, sizeof(addr6), uservaddr);

        state.port = addr6.sin6_port;
        __builtin_memcpy(state.ipv6_addr, addr6.sin6_addr.s6_addr, 16);
    }

    bpf_map_update_elem(&connect_state_map, &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int handle_connect_exit(struct syscall_trace_exit *ctx)
{
    __u64 pid_tgid;
    struct connect_enter_state *state;
    struct connect_event event = {};

    pid_tgid = bpf_get_current_pid_tgid();

    state = bpf_map_lookup_elem(&connect_state_map, &pid_tgid);
    if (!state) {
        return 0;
    }

    event.pid = state->pid;
    event.uid = state->uid;
    event.cgroup_id = state->cgroup_id;

    event.fd = state->fd;
    event.addrlen = state->addrlen;
    event.family = state->family;
    event.port = state->port;
    event.ipv4_addr = state->ipv4_addr;
    __builtin_memcpy(event.ipv6_addr, state->ipv6_addr, sizeof(event.ipv6_addr));
    __builtin_memcpy(event.comm, state->comm, sizeof(event.comm));

    event.ret = (int)ctx->ret;
    event.success = (ctx->ret == 0) ? 1 : 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    bpf_map_delete_elem(&connect_state_map, &pid_tgid);

    return 0;
}