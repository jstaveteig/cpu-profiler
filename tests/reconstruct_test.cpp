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
    // Deliberately unordered input: reconstruction must sort by timestamp.
    std::vector<traceEvent> events{
        makeSwitch(328, 0, worker),          // Worker starts running again.
        makeWake(310, EVENT_WAKEUP),         // Repeated wakeup: must not reset 300.
        makeSwitch(120, worker, 0, 1),      // Worker goes to sleep.
        makeWake(290, EVENT_WAKING),         // Initiation alone changes no state.
        makeSwitch(100, 0, worker),          // Worker starts running.
        makeWake(300, EVENT_WAKEUP),         // Worker becomes runnable.
    };

    const auto intervals = reconstruct(events);
    expectCount(intervals, 3);
    expectInterval(intervals, threadState::Running, 100, 120);
    expectInterval(intervals, threadState::Sleeping, 120, 300);
    expectInterval(intervals, threadState::Runnable, 300, 328);
    std::cout << "PASS: running, sleeping, runnable, ordering, repeated wakeup\n";
}

void testMissingWakeup() {
    std::vector<traceEvent> events{
        makeSwitch(100, 0, worker),
        makeSwitch(120, worker, 0, 1),
        makeSwitch(328, 0, worker),  // No wakeup observed.
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
        std::cout << "All reconstruction tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
