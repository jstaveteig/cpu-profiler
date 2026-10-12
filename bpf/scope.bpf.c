#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u8);
} tracked_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct launchConfig);
} launch_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct captureStats);
} capture_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64[SCOPE_STACK_DEPTH]);
} user_stacks SEC(".maps");

static __always_inline void count_drop(void) {
    __u32 k = 0;
    struct captureStats *s = bpf_map_lookup_elem(&capture_stats, &k);
    if (s) __sync_fetch_and_add(&s->dropped_events, 1);
}
static __always_inline void count_tracking_failure(void) {
    __u32 k = 0;
    struct captureStats *s = bpf_map_lookup_elem(&capture_stats, &k);
    if (s) __sync_fetch_and_add(&s->tracking_failures, 1);
}
static __always_inline int capture_user_stack(void *ctx) {
    int id = bpf_get_stackid(ctx, &user_stacks, BPF_F_USER_STACK);
    if (id < 0) {
        __u32 k = 0;
        struct captureStats *s = bpf_map_lookup_elem(&capture_stats, &k);
        if (s) __sync_fetch_and_add(&s->stack_failures, 1);
    }
    return id;
}

static __always_inline int current_namespace_task_id(int tgid) {
    __u32 key = 0;
    struct launchConfig *cfg = bpf_map_lookup_elem(&launch_config, &key);
    if (!cfg) return -1;
    struct bpf_pidns_info ns = {};
    if (bpf_get_ns_current_pid_tgid(cfg->ns_dev, cfg->ns_ino,
                                    &ns, sizeof(ns)) != 0) return -1;
    return tgid ? (int)ns.tgid : (int)ns.pid;
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    __u32 prev = ctx->prev_pid, next = ctx->next_pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &prev) &&
        !bpf_map_lookup_elem(&tracked_tids, &next)) return 0;
    int stack_id = -1;
    // Stack unwind before ring-buffer reservation
    if (bpf_map_lookup_elem(&tracked_tids, &prev) &&
        ctx->prev_state != 0 && ctx->prev_state != 0x100)
        stack_id = capture_user_stack(ctx);
    struct schedEvent *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { count_drop(); return 0; }
    e->header.type = EVENT_SWITCH;
    e->header.reserved = 0;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->prev_tid = ctx->prev_pid;
    e->next_tid = ctx->next_pid;
    e->prev_state = ctx->prev_state;
    e->cpu = bpf_get_smp_processor_id();
    e->stack_id = stack_id;
    e->reserved = e->reserved2 = e->reserved3 = 0;
    e->process_pid = stack_id >= 0 ? current_namespace_task_id(1) : -1;
    __builtin_memset(e->prev_comm, 0, sizeof(e->prev_comm));
    __builtin_memset(e->next_comm, 0, sizeof(e->next_comm));

    bpf_probe_read_kernel_str(
        e->prev_comm,
        sizeof(e->prev_comm),
        ctx->prev_comm
    );

    bpf_probe_read_kernel_str(
        e->next_comm,
        sizeof(e->next_comm),
        ctx->next_comm
    );
    e->namespace_tid = bpf_map_lookup_elem(&tracked_tids, &prev) ? current_namespace_task_id(0) : -1;
    e->reserved4 = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_waking")
int handle_sched_waking(struct trace_event_raw_sched_wakeup_template *ctx) {
    __u32 target = ctx->pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &target)) return 0;
    int stack_id = capture_user_stack(ctx);
    struct wakeEvent *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { count_drop(); return 0; }
    e->header.type = EVENT_WAKING;
    e->header.reserved = 0;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->target_tid = ctx->pid;
    e->current_tid = (__u32)bpf_get_current_pid_tgid();
    e->cpu = bpf_get_smp_processor_id();
    e->target_cpu = ctx->target_cpu;
    e->reserved = 0;
    e->stack_id = stack_id;
    e->process_pid = stack_id >= 0 ? current_namespace_task_id(1) : -1;
    e->reserved2 = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx) {
    __u32 target = ctx->pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &target)) return 0;
    struct wakeEvent *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { count_drop(); return 0; }
    e->header.type = EVENT_WAKEUP;
    e->header.reserved = 0;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->target_tid = ctx->pid;
    e->current_tid = (__u32)bpf_get_current_pid_tgid();
    e->cpu = bpf_get_smp_processor_id();
    e->target_cpu = ctx->target_cpu;
    e->stack_id = -1;
    e->reserved = e->reserved2 = 0;
    e->process_pid = -1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx) {
    __u32 target = ctx->pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &target)) return 0;
    struct wakeEvent *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { count_drop(); return 0; }
    e->header.type = EVENT_WAKEUP_NEW;
    e->header.reserved = 0;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->target_tid = ctx->pid;
    e->current_tid = (__u32)bpf_get_current_pid_tgid();
    e->cpu = bpf_get_smp_processor_id();
    e->target_cpu = ctx->target_cpu;
    e->stack_id = -1;
    e->reserved = e->reserved2 = 0;
    e->process_pid = -1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent = ctx->parent_pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &parent)) {
        // WSL2: namespaced getpid(), host tracepoint PIDs
        __u32 key = 0;
        struct launchConfig *cfg = bpf_map_lookup_elem(&launch_config, &key);
        if (!cfg || !cfg->armed) return 0;
        struct bpf_pidns_info ns = {};
        if (bpf_get_ns_current_pid_tgid(cfg->ns_dev, cfg->ns_ino,
                                        &ns, sizeof(ns)) != 0) return 0;
        if (ns.pid != cfg->parent_tid) return 0;
    }
    __u32 child = ctx->child_pid;
    __u8 value = 1;
    if (bpf_map_update_elem(&tracked_tids, &child, &value, BPF_ANY) < 0) {
        count_tracking_failure();
        return 0;
    }
    struct forkEvent *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { count_drop(); return 0; }
    e->header.type = EVENT_FORK;
    e->header.reserved = 0;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->parent_tid = ctx->parent_pid;
    e->child_tid = ctx->child_pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 tid = ctx->pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &tid)) return 0;
    struct exitEvent *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { count_drop(); return 0; }
    e->header.type = EVENT_EXIT;
    e->header.reserved = 0;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->tid = ctx->pid;
    e->reserved = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_free")
int handle_sched_free(struct trace_event_raw_sched_process_template *ctx) {
    __u32 tid = ctx->pid;
    bpf_map_delete_elem(&tracked_tids, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
