#ifndef SCOPE_EVENTS_H
#define SCOPE_EVENTS_H

enum eventType {
    EVENT_SWITCH = 1,
    EVENT_WAKING = 2,
    EVENT_WAKEUP = 3,
    EVENT_FORK = 4,
    EVENT_EXIT = 5
};

struct eventHeader {
    uint32_t type;
    uint32_t reserved;
    uint64_t timestamp_ns;
};

struct schedEvent {
    struct eventHeader header;
    int prev_tid;
    int next_tid;
    long long prev_state;
    unsigned int cpu;
    unsigned int reserved;
};

struct wakeEvent {
    struct eventHeader header;

    int32_t target_tid;
    int32_t current_tid;
    uint32_t cpu;
    uint32_t target_cpu;
};

struct forkEvent {
    struct eventHeader header;
    int32_t parent_tid;
    int32_t child_tid;
};

struct exitEvent {
    struct eventHeader header;
    int32_t tid;
    int32_t reserved;
};

#endif