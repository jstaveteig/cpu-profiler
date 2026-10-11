#include "reconstruct.hpp"
#include <unordered_map>
#include <algorithm>

struct activeThread {
    ThreadState state;
    uint64_t since_ns;
    int32_t cpu;
}

std::vector<Interval> reconstruct(
    const std::vector<traceEvent>& events
) {
    std::unordered_map<int32_t, activeThread> active;
    std::vector<Interval> intervals;

    auto transition = [&](int32_t tid,
                        ThreadState newState,
                        uint64_t timestamp,
                        int32_t cpu = -1) {

        if (tid <= 0) {
            return;
        }

        auto it = active.find(tid);

        if (it != active.end()) {
            const ActiveThread& previous = it->second;

            if (timestamp < previous.since_ns) {
                return;
            }

            if (previous.state != ThreadState::Unknown &&
                timestamp > previous.since_ns) {

                intervals.push_back(Interval{
                    tid,
                    previous.since_ns,
                    timestamp,
                    previous.state,
                    previous.cpu
                });
            }
        }

        active[tid] = ActiveThread{
            newState,
            timestamp,
            cpu
        };
    };

    for( const auto& event : events ) {
        if( const auto* sw = std::get_if<schedEvent>(&event)) {
            if (!sw) {
                continue;
            }
            uint64_t timestamp = sw->header.timestamp_ns;
            transition(
                sw->prev_tid,
                ThreadSState::Unknown,
                timestamp
            )

            transition(
                sw->next_tid,
                ThreadState::Running,
                timestamp,
                static_cast<int32_t>(sw->cpu)
            );
        } else if ( const auto* wake = std::get_if<wakeEvent>(&event)) {
            if (!wake) {
                continue;
            }
            uint64_t timestamp = wake->header.timestamp_ns;
            transition(
                wakeEvent->prev_tid,
                ThreadSState::Runnable,
                timestamp
                static_cast<int32_t>(wake->target_cpu)
            )
        }
    }

    return intervals;
}