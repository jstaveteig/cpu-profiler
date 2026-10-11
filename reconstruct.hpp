#pragma once

#include <cstdint>
#include <variant>
#include <vector>
#include "events.h"

using traceEvent = std::variant<schedEvent, wakeEvent>;

enum class threadState {
    Running,
    Runnable,
    Sleeping,
    Other,
    Unknown
};

struct Interval {
    int32_t tid;
    uint64_t start_ns;
    uint64_t end_ns;
    threadState state;
    int32_t cpu = -1;
};

std::vector<Interval> reconstruct(
    const std::vector<traceEvent>& events
);