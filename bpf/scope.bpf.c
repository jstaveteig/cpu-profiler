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

    e->prev_tid = ctx->prev_pid;       // outgoing thread id
    e->next_tid = ctx->next_pid;       // incoming thread id
    e->prev_state = ctx->prev_state;   // outgoing thread's reported state

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";