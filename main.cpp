#include <iostream>
#include <cstring>
#include <cstdio>
#include <csignal>
#include <cerrno>
#include <bpf/libbpf.h>
#include "events.h"
#include "scope.skel.h"

volatile std::sig_atomic_t stopRequested = 0;
static unsigned long long eventCount = 0;


static int handle_event(void* ctx, void* data, size_t data_sz) {
    if (stopRequested) {
        return -EINTR;
    }
    if (data_sz < sizeof(eventHeader)) {
        std::cerr << "Event is too small" << std::endl;
        return -EINVAL;
    }

    eventHeader header{};
    std::memcpy(&header, data, sizeof(header));
    ++eventCount;


    switch (header.type) {
        case EVENT_SWITCH: {
            if (data_sz != sizeof(struct schedEvent)) {
                std::cerr << "Error: Unexpected record size recieved! "
                        << "Expected " << sizeof(struct schedEvent) << "bytes, "
                        << "but got " << data_sz << " bytes." << std::endl;
                return -EINVAL;
            }
            schedEvent event{};
            std::memcpy(&event, data, sizeof(schedEvent));
            if ( eventCount % 1000 == 0 ) {
                std::cout << "SWITCH: "
                        << event.prev_tid << " -> "
                        << event.next_tid << std::endl;
            }
            break;
        }

        case EVENT_WAKING:
        case EVENT_WAKEUP: {
            if (data_sz != sizeof(struct wakeEvent)) {
                std::cerr << "Error: Unexpected record size recieved! "
                        << "Expected " << sizeof(struct wakeEvent) << "bytes, "
                        << "but got " << data_sz << " bytes." << std::endl;
                return -EINVAL;
            }
            wakeEvent event{};
            std::memcpy(&event, data, sizeof(wakeEvent));
            if ( eventCount % 1000 == 0 ) {
                std::cout << (header.type == EVENT_WAKING ? "WAKING" : "WAKEUP")
                        << ": Target " << event.target_tid
                        << ", Current " << event.current_tid << std::endl;
            }
            break;
        }
        default: {
            std::cerr << "Error: Unexpected record type recieved! " << std::endl;
            return -EINVAL;
        }
    }

    return 0;
}

void handleSignInt(int signal) {
    if (signal == SIGINT) {
        stopRequested = 1;
    }
}

int main() {
    if (std::signal(SIGINT, handleSignInt) == SIG_ERR) {
        std::cerr << "Failed to register signal handler" << std::endl;
        return 1;
    }
    struct scope_bpf* skel = scope_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to load BPF program" << std::endl;
        return 1;
    }


    struct ring_buffer* rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        nullptr,
        nullptr
    );
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        scope_bpf__destroy(skel);
        return 1;
    }
    int err = scope_bpf__attach(skel);
    if( err < 0 ) {
        ring_buffer__free(rb);
        scope_bpf__destroy(skel);
        std::cerr << "Failed to attach BPF program: "
                << std::strerror(-err) << std::endl;
        return 1;
    }

    int exitCode = 0;

    while (!stopRequested) {
        int result = ring_buffer__poll(rb, 100);
        if (result == -EINTR) {
            if (stopRequested) {
                break;
            }
            continue;
        }

        if (result < 0) {
            std::cerr << "Ring buffer polling failed: "
                    << result << std::endl;
            exitCode = 1;
            break;
        }
    }
    ring_buffer__free(rb);
    scope_bpf__destroy(skel);
    return exitCode;
}