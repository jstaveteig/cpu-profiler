#include "recording.hpp"
#include "scope_span.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <filesystem>
#include <stdexcept>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

int main() {
    const auto path = (std::filesystem::temp_directory_path() / "scope_span_test_v4.scope").string();
    std::filesystem::remove(path);
    int fd[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_NONBLOCK, 0, fd)) return 1;
    setenv("SCOPE_SPAN_FD", std::to_string(fd[1]).c_str(), 1);
    {
        scope::Span span("handle_request");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    unsetenv("SCOPE_SPAN_FD");
    close(fd[1]);
    spanEvent start{}, stop{};
    if (recv(fd[0], &start, sizeof(start), 0) != sizeof(start) ||
        recv(fd[0], &stop, sizeof(stop), 0) != sizeof(stop)) return 2;
    close(fd[0]);
    if (start.header.type != EVENT_SPAN || stop.header.type != EVENT_SPAN ||
        start.phase != 1 || stop.phase != 2 ||
        stop.header.timestamp_ns < start.header.timestamp_ns ||
        start.span_id != stop.span_id ||
        std::string(start.name) != "handle_request" ||
        start.namespace_tid <= 0) return 3;
    schedEvent sw{};
    sw.header.type = EVENT_SWITCH;
    sw.header.timestamp_ns = start.header.timestamp_ns;
    sw.prev_tid = 444;
    sw.next_tid = 555;
    sw.namespace_tid = 123;
    std::memcpy(sw.prev_comm, "worker-pool", 12);
    {
        RecordingWriter writer(path);
        writer.append(sw);
        writer.append(start);
        writer.append(stop);
        RecordingQuality quality{};
        quality.complete = true;
        writer.finish(quality);
    }
    const auto data = loadRecording(path);
    if (data.size() != 3) return 4;
    const auto& readSw = std::get<schedEvent>(data[0]);
    if (std::string(readSw.prev_comm) != "worker-pool" || readSw.namespace_tid != 123) return 5;
    const auto& readSpan = std::get<spanEvent>(data[1]);
    if (std::string(readSpan.name) != "handle_request" || readSpan.span_id != start.span_id) return 6;
    std::filesystem::remove(path);
    std::cout << "PASS: named spans and thread comm round-trip\n";
    return 0;
}
