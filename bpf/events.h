#ifndef SCOPE_EVENTS_H
#define SCOPE_EVENTS_H

struct schedEvent {
    unsigned long long timestamp_ns;
    int prev_tid;
    int next_tid;
    long long prev_state;
    unsigned int cpu;
    unsigned int reserved;
};

#endif