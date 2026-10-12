#ifndef SCOPE_EVENTS_H
#define SCOPE_EVENTS_H

// This wire header is consumed by restricted-C BPF and C++20.
#if defined(SCOPE_BPF_TARGET)
typedef __u8 scope_u8;
typedef __u32 scope_u32;
typedef __s32 scope_s32;
typedef __u64 scope_u64;
typedef __s64 scope_s64;
#else
#include <stdint.h>
typedef uint8_t scope_u8;
typedef uint32_t scope_u32;
typedef int32_t scope_s32;
typedef uint64_t scope_u64;
typedef int64_t scope_s64;
#endif

enum EventType {
    EVENT_SWITCH = 1,
    EVENT_WAKING = 2,
    EVENT_WAKEUP = 3,
    EVENT_FORK = 4,
    EVENT_EXIT = 5,
    EVENT_WAKEUP_NEW = 6
};

struct eventHeader {
    scope_u32 type;
    scope_u32 reserved;
    scope_u64 timestamp_ns;
};

struct schedEvent {
    struct eventHeader header;
    scope_s32 prev_tid;
    scope_s32 next_tid;
    scope_s64 prev_state;
    scope_u32 cpu;
    scope_s32 stack_id; // Outgoing thread's user stack at switch-out; negative if absent
    scope_u32 reserved;
    scope_u32 reserved2;
    scope_s32 process_pid; // Namespace-local TGID for captured switch-out stack
    scope_u32 reserved3;
};

struct wakeEvent {
    struct eventHeader header;
    scope_s32 target_tid;
    scope_s32 current_tid; // Event context; waking context only for EVENT_WAKING
    scope_u32 cpu;
    scope_u32 target_cpu;
    scope_s32 stack_id; // Current context's user stack for EVENT_WAKING only
    scope_u32 reserved;
    scope_s32 process_pid; // Namespace-local TGID for waking-context stack
    scope_u32 reserved2;
};

struct forkEvent {
    struct eventHeader header;
    scope_s32 parent_tid;
    scope_s32 child_tid;
};

struct exitEvent {
    struct eventHeader header;
    scope_s32 tid;
    scope_s32 reserved;
};

struct launchConfig {
    scope_u64 ns_dev;
    scope_u64 ns_ino;
    scope_u32 parent_tid; // Namespace-local userspace PID of scope
    scope_u32 armed;
};

struct captureStats {
    scope_u64 dropped_events;
    scope_u64 tracking_failures;
    scope_u64 stack_failures;
};

#define SCOPE_STACK_DEPTH 16

#ifdef __cplusplus
static_assert(sizeof(eventHeader) == 16);
static_assert(sizeof(schedEvent) == 56);
static_assert(sizeof(wakeEvent) == 48);
static_assert(sizeof(forkEvent) == 24);
static_assert(sizeof(exitEvent) == 24);
#endif
#endif
