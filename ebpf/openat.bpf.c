#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct openat_event {
    __u32 pid;
    __u32 uid;
    int dfd;
    int flags;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

struct syscall_trace_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct syscall_trace_enter *ctx)
{
    struct openat_event event = {};
    const char *filename_ptr;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    event.dfd = (int)ctx->args[0];
    filename_ptr = (const char *)ctx->args[1];
    event.flags = (int)ctx->args[2];

    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}