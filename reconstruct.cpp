#include "reconstruct.hpp"
#include <iostream>
#include <unordered_map>
#include <algorithm>

struct activeThread {
    threadState state;
    uint64_t since_ns;
    int32_t cpu;
    uint64_t lifetime_id = 0;
    bool exiting = false;
};

enum class TransitionSource {
    SwitchOut,
    SwitchIn,
    Wakeup
};

auto decodeState = [](int64_t state) {
    if (state == 0 || state == 0x100) {
        return threadState::Runnable;
    }

    if (state == 1 || state == 2) {
        return threadState::Sleeping;
    }

    return threadState::Other;
};

std::vector<Interval> reconstruct(
    const std::vector<traceEvent>& events
) {
    // Local copy for sorting
    std::vector<traceEvent> sortedEvents = events;

    // Timestamp order
    std::stable_sort(
        sortedEvents.begin(),
        sortedEvents.end(),
        [](const traceEvent& a, const traceEvent& b) {
            auto getTimestamp = [](const traceEvent& event) {
                return std::visit(
                    [](const auto& e) {
                        return e.header.timestamp_ns;
                    },
                    event
                );
            };

            return getTimestamp(a) < getTimestamp(b);
        }
    );

    std::unordered_map<int32_t, activeThread> active;
    std::vector<Interval> intervals;
    uint64_t nextLifetimeId = 1;

    size_t inconsistencies = 0;
    size_t repeated = 0;

    auto transition = [&](int32_t tid,
                        threadState newState,
                        uint64_t timestamp,
                        int32_t cpu,
                        TransitionSource source) {


        if (tid <= 0) {
            return;
        }

        auto it = active.find(tid);

        if (it == active.end()) {
            active.emplace(tid, activeThread{
                newState,
                timestamp,
                cpu,
                nextLifetimeId++,
                false
            });

            return;
        }

        activeThread& previous = it->second;

        if (timestamp < previous.since_ns) {
            ++inconsistencies;
            return;
        }

        bool finalSwitchOut =
            source == TransitionSource::SwitchOut && previous.exiting;

        if (!finalSwitchOut &&
            previous.state == newState &&
            (newState != threadState::Running || previous.cpu == cpu)) {

            ++repeated;
            return;
        }

        bool valid = false;

        switch (source) {
            case TransitionSource::SwitchOut:
                valid = previous.state == threadState::Running ||
                        previous.state == threadState::Unknown;
                break;

            case TransitionSource::SwitchIn:
                valid = previous.state == threadState::Runnable ||
                        previous.state == threadState::Unknown;
                break;

            case TransitionSource::Wakeup:
                valid = previous.state == threadState::Sleeping ||
                        previous.state == threadState::Unknown;
                break;
        }

        if (source == TransitionSource::Wakeup && !valid) {
            ++inconsistencies;
            return;
        }

        if (timestamp > previous.since_ns) {
            intervals.push_back(Interval{
                tid,
                previous.since_ns,
                timestamp,
                valid ? previous.state : threadState::Unknown,
                valid ? previous.cpu : -1,
                previous.lifetime_id
            });
        }   

        if (!valid) {
            ++inconsistencies;
        }

        if (finalSwitchOut) {
            active.erase(it);
            return;
        }

        previous = activeThread{
            newState,
            timestamp,
            cpu,
            previous.lifetime_id,
            previous.exiting
        };
    };

    for (const auto& event : sortedEvents) {
        if( const auto* sw = std::get_if<schedEvent>(&event)) {
            uint64_t timestamp = sw->header.timestamp_ns;
            transition(
                sw->prev_tid,
                decodeState(sw->prev_state),
                timestamp,
                -1,
                TransitionSource::SwitchOut
            );

            transition(
                sw->next_tid,
                threadState::Running,
                timestamp,
                static_cast<int32_t>(sw->cpu),
                TransitionSource::SwitchIn
            );
        } else if ( const auto* wake = std::get_if<wakeEvent>(&event)) {
            if (wake->header.type == EVENT_WAKEUP ||
            wake->header.type == EVENT_WAKEUP_NEW) {
                transition(
                    wake->target_tid,
                    threadState::Runnable,
                    wake->header.timestamp_ns,
                    -1,
                    TransitionSource::Wakeup
                );
            }
        } else if ( const auto* fork = std::get_if<forkEvent>(&event)) {
            int32_t tid = fork->child_tid;

            if (tid <= 0) {
                continue;
            }

            if (active.contains(tid)) {
                ++inconsistencies;
                active.erase(tid);
            }

            active.emplace(tid, activeThread{
                threadState::Unknown,
                fork->header.timestamp_ns,
                -1,
                nextLifetimeId++,
                false
            });
        } else if (const auto* exited = std::get_if<exitEvent>(&event)) {
            auto it = active.find(exited->tid);

            if (it != active.end()) {
                it->second.exiting = true;
            }
        }
    }


    for (const auto& interval : intervals) {
        std::cerr
            << "Interval: tid=" << interval.tid
            << " start=" << interval.start_ns
            << " end=" << interval.end_ns
            << " state=" << static_cast<int>(interval.state)
            << '\n';
    }

    return intervals;
}