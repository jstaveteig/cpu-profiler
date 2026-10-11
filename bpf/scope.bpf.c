#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch( struct trace_event_raw_sched_switch *ctx ) {
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


char LICENSE[] SEC("license") = "Dual BSD/GPL";