#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1684);
    __type(key, __u32);
    __type(value, __u8);
} tracked_tids SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch( struct trace_event_raw_sched_switch *ctx ) {
    __u32 prev = ctx->prev_pid;
    __u32 next = ctx->next_pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &prev) ||
        !bpf_map_lookup_elem(&tracked_tids, &next) ) {
        return 0;
    }

    struct schedEvent *e;

    e = bpf_ringbuf_reserve(&events, sizeof(struct schedEvent), 0);

    if (!e) {
        return 0;
    }

    e->header.type = EVENT_SWITCH;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->header.reserved = 0;
    e->prev_tid = ctx->prev_pid;       // outgoing thread id
    e->next_tid = ctx->next_pid;       // incoming thread id
    e->prev_state = ctx->prev_state;   // outgoing thread's reported state
    e->cpu = bpf_get_smp_processor_id();
    e->reserved = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_waking")
int handle_sched_waking( struct trace_event_raw_sched_wakeup_template *ctx ) {
    __u32 target = ctx->pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &target) ) {
        return 0;
    }

    struct wakeEvent *e;

    e = bpf_ringbuf_reserve(&events, sizeof(struct wakeEvent), 0);
    if (!e) {
        return 0;
    }

    e->header.type = EVENT_WAKING;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->header.reserved = 0;
    e->target_tid = ctx->pid;
    // bitmask and take only the first 32 bits of current pid
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    e->current_tid = tid;
    e->cpu = bpf_get_smp_processor_id();
    e->target_cpu = ctx->target_cpu;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup( struct trace_event_raw_sched_wakeup_template *ctx ) {
    __u32 target = ctx->pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &target) ) {
        return 0;
    }
    struct wakeEvent *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct wakeEvent), 0);
    if (!e) {
        return 0;
    }

    e->header.type = EVENT_WAKEUP;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->header.reserved = 0;
    e->target_tid = ctx->pid;
    // bitmask and take only the first 32 bits of current pid
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    e->current_tid = tid;
    e->cpu = bpf_get_smp_processor_id();
    e->target_cpu = ctx->target_cpu;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent = ctx->parent_pid;

    if (!bpf_map_lookup_elem(&tracked_tids, &parent)) {
        return 0;
    }

    __u32 child = ctx->child_pid;
    __u8 value = 1;

    int ret = bpf_map_update_elem(
        &tracked_tids,
        &child,
        &value,
        BPF_ANY
    );

    if (ret < 0) {
        return 0;
    }

    struct forkEvent *e = bpf_ringbuf_reserve(
        &events,
        sizeof(struct forkEvent),
        0
    );

    if (!e) {
        return 0;
    }

    e->header.type = EVENT_FORK;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->header.reserved = 0;

    e->parent_tid = ctx->parent_pid;
    e->child_tid = ctx->child_pid;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_exit(  struct trace_event_raw_sched_process_template *ctx ) {
    __u32 tid = ctx->pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &tid) ) {
        return 0;
    }
    struct exitEvent *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct exitEvent), 0);
    if (!e) {
        return 0;
    }

    e->header.type = EVENT_EXIT;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->header.reserved = 0;
    e->tid = ctx->pid;
    e->reserved = 0;
    
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/sched/sched_process_free")
int handle_sched_free(  struct trace_event_raw_sched_process_template *ctx ) {
    __u32 tid = ctx->pid;
    bpf_map_delete_elem(&tracked_tids, &tid);

    return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new( struct trace_event_raw_sched_wakeup_template *ctx ) {
    __u32 target = ctx->pid;
    if (!bpf_map_lookup_elem(&tracked_tids, &target) ) {
        return 0;
    }
    struct wakeEvent *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct wakeEvent), 0);
    if (!e) {
        return 0;
    }

    e->header.type = EVENT_WAKEUP_NEW;
    e->header.timestamp_ns = bpf_ktime_get_ns();
    e->header.reserved = 0;
    e->target_tid = ctx->pid;
    // bitmask and take only the first 32 bits of current pid
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    e->current_tid = tid;
    e->cpu = bpf_get_smp_processor_id();
    e->target_cpu = ctx->target_cpu;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";