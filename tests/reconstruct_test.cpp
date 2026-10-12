#include "reconstruct.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr std::uint64_t ms = 1'000'000;
constexpr std::int32_t worker = 123;

schedEvent makeSwitch(std::uint64_t time_ms, std::int32_t prev,
                      std::int32_t next, std::int64_t prev_state = 0,
                      std::uint32_t cpu = 2) {
    schedEvent event{};
    event.header.type = EVENT_SWITCH;
    event.header.timestamp_ns = time_ms * ms;
    event.prev_tid = prev;
    event.next_tid = next;
    event.prev_state = prev_state;
    event.cpu = cpu;
    return event;
}

wakeEvent makeWake(std::uint64_t time_ms, std::uint32_t type) {
    wakeEvent event{};
    event.header.type = type;
    event.header.timestamp_ns = time_ms * ms;
    event.target_tid = worker;
    event.current_tid = 999;
    event.cpu = 2;
    event.target_cpu = 2;
    return event;
}

forkEvent makeFork(uint64_t time_ms, int32_t parent, int32_t child) {
    forkEvent event{};
    event.header.type = EVENT_FORK;
    event.header.timestamp_ns = time_ms * ms;
    event.parent_tid = parent;
    event.child_tid = child;
    return event;
}

exitEvent makeExit(uint64_t time_ms, int32_t tid) {
    exitEvent event{};
    event.header.type = EVENT_EXIT;
    event.header.timestamp_ns = time_ms * ms;
    event.tid = tid;
    return event;
}


void expectInterval(const std::vector<Interval>& intervals,
                    threadState state, std::uint64_t start_ms,
                    std::uint64_t end_ms) {
    const auto found = std::find_if(intervals.begin(), intervals.end(),
        [&](const Interval& interval) {
            return interval.tid == worker &&
                   interval.state == state &&
                   interval.start_ns == start_ms * ms &&
                   interval.end_ns == end_ms * ms;
        });
    if (found == intervals.end()) {
        throw std::runtime_error("Missing expected interval for thread 123: " +
                                 std::to_string(start_ms) + " -> " +
                                 std::to_string(end_ms) + " ms");
    }
}

void expectCount(const std::vector<Interval>& intervals, std::size_t expected) {
    const auto count = std::count_if(intervals.begin(), intervals.end(),
        [](const Interval& interval) { return interval.tid == worker; });
    if (static_cast<std::size_t>(count) != expected) {
        throw std::runtime_error("Expected " + std::to_string(expected) +
                                 " intervals for thread 123, got " +
                                 std::to_string(count));
    }
}

void testNormalWaitAndOrdering() {
    std::vector<traceEvent> events{
        makeSwitch(328, 0, worker),          // Worker running again
        makeWake(310, EVENT_WAKEUP),         // Repeated wakeup; timestamp still 300
        makeSwitch(120, worker, 0, 1),      // Worker asleep
        makeWake(290, EVENT_WAKING),         // Wake initiation; state unchanged
        makeSwitch(100, 0, worker),          // Worker running
        makeWake(300, EVENT_WAKEUP),         // Worker runnable

    };

    const auto intervals = reconstruct(events);
    expectCount(intervals, 3);
    expectInterval(intervals, threadState::Running, 100, 120);
    expectInterval(intervals, threadState::Sleeping, 120, 300);
    expectInterval(intervals, threadState::Runnable, 300, 328);
    std::cout << "PASS: running, sleeping, runnable, ordering, repeated wakeup\n";
}

void testForkExitTidReuse() {
    std::vector<traceEvent> events{
        makeFork(100, 100, 450),
        makeSwitch(110, 0, 450),
        makeExit(150, 450),
        makeSwitch(155, 450, 0),

        makeFork(300, 100, 450),
        makeSwitch(320, 0, 450),
        makeSwitch(350, 450, 0)
    };

    auto intervals = reconstruct(events);

    const Interval* first = nullptr;
    const Interval* second = nullptr;

    for (const auto& interval : intervals) {
        if (interval.tid != 450) {
            continue;
        }

        if (interval.start_ns < 300 * ms &&
            interval.end_ns > 155 * ms) {
            throw std::runtime_error("Interval crosses thread lifetimes");
        }

        if (interval.state != threadState::Running) {
            continue;
        }

        if (interval.start_ns == 110 * ms &&
            interval.end_ns == 155 * ms) {
            first = &interval;
        }

        if (interval.start_ns == 320 * ms &&
            interval.end_ns == 350 * ms) {
            second = &interval;
        }
    }

    if (!first || !second) {
        throw std::runtime_error("Missing expected running intervals");
    }

    if (first->lifetime_id == 0 ||
        second->lifetime_id == 0 ||
        first->lifetime_id == second->lifetime_id) {
        throw std::runtime_error("Thread lifetimes were not separated");
    }

    std::cout << "PASS: fork, exit, and TID reuse\n";
}

void testMissingWakeup() {
    std::vector<traceEvent> events{
        makeSwitch(100, 0, worker),
        makeSwitch(120, worker, 0, 1),
        makeSwitch(328, 0, worker),  // Missing wakeup
    };

    const auto intervals = reconstruct(events);
    expectCount(intervals, 2);
    expectInterval(intervals, threadState::Running, 100, 120);
    expectInterval(intervals, threadState::Unknown, 120, 328);
    std::cout << "PASS: missing wakeup is not guessed as sleeping/runnable\n";
}
} // namespace

int main() {
    try {
        testNormalWaitAndOrdering();
        testMissingWakeup();
        testForkExitTidReuse();
        std::cout << "All reconstruction tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
