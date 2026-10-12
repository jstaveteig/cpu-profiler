#pragma once
// Optional Scope markers via inherited nonblocking socket (SCOPE_SPAN_FD)
#include "bpf/events.h"
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

namespace scope {
class Span {
public:
    explicit Span(const char* name) noexcept : name_(name) {
        static std::atomic<unsigned> sequence{1};
        id_ = (static_cast<scope_u64>(::getpid()) << 32) | sequence.fetch_add(1);
        sendMarker(1);
    }
    ~Span() noexcept { sendMarker(2); }
    Span(const Span&) = delete;
    Span& operator=(const Span&) = delete;

private:
    const char* name_;
    scope_u64 id_{};
    void sendMarker(scope_u32 phase) const noexcept {
        const char* env = ::getenv("SCOPE_SPAN_FD");
        if (!env || !*env) return;
        char* end = nullptr;
        const long fd = ::strtol(env, &end, 10);
        if (!end || *end || fd < 0 || fd > 1048576) return;
        timespec now{};
        if (::clock_gettime(CLOCK_MONOTONIC, &now) != 0) return;
        spanEvent marker{};
        marker.header.type = EVENT_SPAN;
        marker.header.timestamp_ns = static_cast<scope_u64>(now.tv_sec) * 1000000000ULL + now.tv_nsec;
        marker.span_id = id_;
        marker.namespace_tid = static_cast<scope_s32>(::syscall(SYS_gettid));
        marker.phase = phase;
        if (name_) {
            // Fixed-size names, no allocation
            for (unsigned i = 0; i + 1 < sizeof(marker.name) && name_[i]; ++i)
                marker.name[i] = name_[i];
        }
        // Atomic datagram, dropped if the recorder falls behind
        (void)::send(static_cast<int>(fd), &marker, sizeof(marker), MSG_DONTWAIT | MSG_NOSIGNAL);
    }
};
} // namespace scope
