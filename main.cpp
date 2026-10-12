#include "recording.hpp"
#include "scope.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <iostream>
#include <memory>
#include <pwd.h>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_set>
#include <type_traits>
#include <array>
#include <chrono>
#include <thread>
#include <fstream>
#include <functional>
#include <sstream>
#include <sys/sysmacros.h>
#include <time.h>
#include <sys/socket.h>

namespace {
volatile std::sig_atomic_t stopRequested = 0;
void handleSigint(int signal) { if (signal == SIGINT) stopRequested = 1; }

struct CaptureContext {
    RecordingWriter* writer = nullptr;
    int stackMapFd = -1;
    std::unordered_set<std::int32_t> savedStacks;
    std::string error;
    std::function<void()> drainMarkers;
    unsigned eventsSinceDrain = 0;
};

int handleEvent(void* ctx, void* data, size_t size) {
    auto& c = *static_cast<CaptureContext*>(ctx);
    if (size < sizeof(eventHeader)) return -EINVAL;
    eventHeader h{};
    std::memcpy(&h, data, sizeof(h));
    try {
        if (++c.eventsSinceDrain >= 64 && c.drainMarkers) {
            c.eventsSinceDrain = 0;
            c.drainMarkers();
        }
        auto store = [&]<typename T>() -> int {
            if (size != sizeof(T)) return -EINVAL;
            T e{};
            std::memcpy(&e, data, sizeof(e));
            if constexpr (std::is_same_v<T, schedEvent> || std::is_same_v<T, wakeEvent>) {
                if (e.stack_id >= 0 && c.savedStacks.insert(e.stack_id).second) {
                    std::array<std::uint64_t, SCOPE_STACK_DEPTH> pcs{};
                    if (bpf_map_lookup_elem(c.stackMapFd, &e.stack_id, pcs.data()) == 0)
                        c.writer->storeStack(e.stack_id, pcs);
                    // Stack ID retained on lookup failure
                }
            }
            c.writer->append(e);
            return 0;
        };
        switch (h.type) {
            case EVENT_SWITCH: return store.operator()<schedEvent>();
            case EVENT_WAKING: case EVENT_WAKEUP: case EVENT_WAKEUP_NEW:
                return store.operator()<wakeEvent>();
            case EVENT_FORK: return store.operator()<forkEvent>();
            case EVENT_EXIT: return store.operator()<exitEvent>();
            default: return -EINVAL;
        }
    } catch (const std::exception& e) {
        c.error = e.what();
        return -EIO;
    }
}

struct BpfCleanup { void operator()(scope_bpf* p) const { scope_bpf__destroy(p); } };
struct RingCleanup { void operator()(ring_buffer* p) const { ring_buffer__free(p); } };

struct Identity {
    uid_t uid = 0;
    gid_t gid = 0;
    std::string user;
};

Identity sudoIdentity() {
    if (geteuid() != 0) throw std::runtime_error("Run the recorder with sudo");
    const char* uidText = std::getenv("SUDO_UID");
    const char* gidText = std::getenv("SUDO_GID");
    if (!uidText || !gidText) throw std::runtime_error("Missing sudo identity");
    Identity i;
    auto parse = [](const char* text, auto& value) {
        const char* end = text + std::strlen(text);
        const auto [p, error] = std::from_chars(text, end, value);
        if (error != std::errc{} || p != end || value == 0)
            throw std::runtime_error("Invalid sudo identity");
    };
    parse(uidText, i.uid);
    parse(gidText, i.gid);
    passwd* pw = getpwuid(i.uid);
    if (!pw || !pw->pw_name) throw std::runtime_error("Cannot resolve sudo account");
    i.user = pw->pw_name;
    return i;
}

// Sampled executable mappings; short-lived mappings may be missed
std::vector<ExecutableMapping> executableMaps(pid_t pid) {
    std::ifstream stream("/proc/" + std::to_string(pid) + "/maps");
    std::vector<ExecutableMapping> maps;
    if (!stream) return maps;
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return maps;
    const std::uint64_t observed = std::uint64_t(now.tv_sec) * 1'000'000'000 + now.tv_nsec;
    std::string line;
    while (std::getline(stream, line)) {
        std::istringstream input(line);
        std::string range, perms, offset, device, inode, path;
        if (!(input >> range >> perms >> offset >> device >> inode)) continue;
        std::getline(input >> std::ws, path);
        if (perms.size() < 3 || perms[2] != 'x' || path.empty() || path[0] != '/') continue;
        const auto dash = range.find('-');
        if (dash == std::string::npos) continue;
        try {
            ExecutableMapping map;
            map.process_pid = pid;
            map.observed_ns = observed;
            map.start = std::stoull(range.substr(0, dash), nullptr, 16);
            map.end = std::stoull(range.substr(dash + 1), nullptr, 16);
            map.file_offset = std::stoull(offset, nullptr, 16);
            map.inode = std::stoull(inode);
            map.path = path;
            if (map.end <= map.start || map.path.find(" (deleted)") != std::string::npos) continue;
            struct stat st{};
            if (stat(map.path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
            if (map.inode != static_cast<std::uint64_t>(st.st_ino)) continue;
            map.device = static_cast<std::uint64_t>(st.st_dev);
            map.modified_ns = static_cast<std::int64_t>(st.st_mtim.tv_sec) * 1'000'000'000
                              + st.st_mtim.tv_nsec;
            maps.push_back(std::move(map));
        } catch (const std::exception&) { /* Malformed procfs line */ }
    }
    return maps;
}

std::string mappingFingerprint(const std::vector<ExecutableMapping>& maps) {
    std::string result;
    for (const auto& m : maps)
        result += m.path + ":" + std::to_string(m.start) + ":" +
                  std::to_string(m.end) + ":" + std::to_string(m.file_offset) + ":" +
                  std::to_string(m.inode) + ":" + std::to_string(m.modified_ns) + ";";
    return result;
}

int waitForChild(pid_t child, int& status) {
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited == -1 && errno == EINTR);
    return waited == child ? 0 : -1;
}
} // namespace

int main(int argc, char* argv[]) {
    if (argc < 4 || std::strcmp(argv[1], "run") != 0 || std::strcmp(argv[2], "--") != 0) {
        std::cerr << "Usage: scope run -- <command> [arguments...]\n";
        return 1;
    }
    try {
        const Identity identity = sudoIdentity();
        if (std::signal(SIGINT, handleSigint) == SIG_ERR)
            throw std::runtime_error("Could not install SIGINT handler");
        std::unique_ptr<scope_bpf, BpfCleanup> skel(scope_bpf__open_and_load());
        if (!skel) throw std::runtime_error("Could not load eBPF probes");
        if (scope_bpf__attach(skel.get()) < 0)
            throw std::runtime_error("Could not attach eBPF probes");

        const int stackMap = bpf_map__fd(skel->maps.user_stacks);
        if (stackMap < 0) throw std::runtime_error("Could not access BPF stack map");

        int syncPipe[2]{};
        if (pipe2(syncPipe, O_CLOEXEC) != 0)
            throw std::runtime_error("Could not create launch pipe");
        // Optional spans over nonblocking datagrams
        int markerSockets[2]{};
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                       0, markerSockets) != 0) {
            close(syncPipe[0]); close(syncPipe[1]);
            throw std::runtime_error("Could not create span channel");
        }
        const int markerBuffer = 1024 * 1024;
        setsockopt(markerSockets[1], SOL_SOCKET, SO_SNDBUF, &markerBuffer, sizeof(markerBuffer));

        struct stat ns{};
        if (stat("/proc/self/ns/pid", &ns) != 0) {
            close(syncPipe[0]); close(syncPipe[1]);
            throw std::runtime_error("Could not inspect PID namespace");
        }
        launchConfig cfg{};
        cfg.ns_dev = static_cast<std::uint64_t>(ns.st_dev);
        cfg.ns_ino = static_cast<std::uint64_t>(ns.st_ino);
        cfg.parent_tid = static_cast<std::uint32_t>(getpid());
        cfg.armed = 1;
        std::uint32_t key = 0;
        const int launchFd = bpf_map__fd(skel->maps.launch_config);
        if (launchFd < 0 || bpf_map_update_elem(launchFd, &key, &cfg, BPF_ANY) != 0) {
            close(syncPipe[0]); close(syncPipe[1]);
            throw std::runtime_error("Could not arm launch tracking");
        }

        pid_t child = fork();
        if (child == 0) {
            close(syncPipe[1]);
            close(markerSockets[0]);
            char ready = 0;
            ssize_t n;
            do { n = read(syncPipe[0], &ready, 1); } while (n < 0 && errno == EINTR);
            close(syncPipe[0]);
            if (n != 1 || ready != 'R') _exit(126);
            if (initgroups(identity.user.c_str(), identity.gid) != 0 ||
                setresgid(identity.gid, identity.gid, identity.gid) != 0 ||
                setresuid(identity.uid, identity.uid, identity.uid) != 0)
                _exit(126);
            // Marker socket inherited across exec for scope::Span
            const int fdFlags = fcntl(markerSockets[1], F_GETFD);
            if (fdFlags < 0 || fcntl(markerSockets[1], F_SETFD, fdFlags & ~FD_CLOEXEC) != 0)
                _exit(126);
            const std::string markerFd = std::to_string(markerSockets[1]);
            if (setenv("SCOPE_SPAN_FD", markerFd.c_str(), 1) != 0) _exit(126);
            execvp(argv[3], &argv[3]);
            _exit(127);
        }
        close(syncPipe[0]);
        close(markerSockets[1]);
        if (child < 0) {
            close(syncPipe[1]);
            throw std::runtime_error("fork() failed");
        }

        // Partial recording retained on failure, marked incomplete
        // Child blocked until SQLite and process tracking are ready
        std::unique_ptr<RecordingWriter> writer;
        try {
            writer = std::make_unique<RecordingWriter>("recording.scope");
            cfg.armed = 0;
            if (bpf_map_update_elem(launchFd, &key, &cfg, BPF_ANY) != 0)
                throw std::runtime_error("Could not disarm launch tracking");
        } catch (...) {
            close(syncPipe[1]);
            int status = 0;
            waitForChild(child, status);
            throw;
        }

        CaptureContext capture{writer.get(), stackMap, {}, {}};
        std::unique_ptr<ring_buffer, RingCleanup> ring(ring_buffer__new(
            bpf_map__fd(skel->maps.events), handleEvent, &capture, nullptr));
        if (!ring) {
            close(syncPipe[1]);
            int status = 0; waitForChild(child, status);
            throw std::runtime_error("Cannot read BPF ring buffer");
        }
        if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
            close(syncPipe[1]);
            int status = 0; waitForChild(child, status);
            throw std::runtime_error("Could not ignore SIGPIPE");
        }
        char release = 'R';
        const auto sent = write(syncPipe[1], &release, 1);
        close(syncPipe[1]);
        if (sent != 1) {
            int status = 0; waitForChild(child, status);
            throw std::runtime_error("Could not release target process");
        }

        auto drainMarkers = [&] {
            for (;;) {
                spanEvent marker{};
                ssize_t n = recv(markerSockets[0], &marker, sizeof(marker), MSG_DONTWAIT | MSG_TRUNC);
                if (n < 0 && errno == EINTR) continue;
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                if (n < 0) throw std::runtime_error("Span channel read failed");
                if (n == sizeof(marker) && marker.header.type == EVENT_SPAN &&
                    (marker.phase == 1 || marker.phase == 2) && marker.name[sizeof(marker.name)-1] == 0) {
                    writer->append(marker);
                }
            }
        };
        capture.drainMarkers = drainMarkers;
        std::string previousMaps;
        auto lastMapRead = std::chrono::steady_clock::time_point{};
        int status = 0;
        bool childExited = false;
        bool captureFailed = false;
        pollfd inputs[] = {{ring_buffer__epoll_fd(ring.get()), POLLIN, 0},
                           {markerSockets[0], POLLIN, 0}};
        while (!stopRequested) {
            int ready = poll(inputs, 2, 30);
            if (ready < 0 && errno != EINTR) {
                captureFailed = true;
                break;
            }
            try { drainMarkers(); }
            catch (const std::exception& e) { std::cerr << e.what() << '\n'; captureFailed = true; break; }
            int result = ring_buffer__consume(ring.get());
            if (result < 0 && result != -EINTR) {
                std::cerr << "Capture failed: "
                          << (capture.error.empty() ? std::to_string(result) : capture.error) << '\n';
                captureFailed = true;
                break;
            }
            try { drainMarkers(); }
            catch (const std::exception& e) { std::cerr << e.what() << '\n'; captureFailed = true; break; }
            // Low-rate mapping snapshots, stored on change
            const auto now = std::chrono::steady_clock::now();
            if (now - lastMapRead >= std::chrono::milliseconds(30)) {
                lastMapRead = now;
                const auto maps = executableMaps(child);
                const auto signature = mappingFingerprint(maps);
                if (!maps.empty() && signature != previousMaps) {
                    try {
                        writer->storeMappings(maps);
                        previousMaps = signature;
                    } catch (const std::exception& e) {
                        std::cerr << "Cannot save executable mappings: " << e.what() << '\n';
                        captureFailed = true;
                        break;
                    }
                }
            }
            pid_t finished = waitpid(child, &status, WNOHANG);
            if (finished == child) { childExited = true; break; }
            if (finished == -1 && errno != EINTR) { captureFailed = true; break; }
        }
        if (!childExited) {
            // Direct-child supervision only
            if (kill(child, SIGTERM) != 0 && errno != ESRCH) captureFailed = true;
            // Bounded shutdown after TERM
            for (int attempt = 0; attempt < 40; ++attempt) {
                const auto waited = waitpid(child, &status, WNOHANG);
                if (waited == child) { childExited = true; break; }
                if (waited < 0 && errno != EINTR) { captureFailed = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            if (!childExited) {
                kill(child, SIGKILL);
                if (waitForChild(child, status) == 0) childExited = true;
                else captureFailed = true;
            }
        }

        try { drainMarkers(); }
        catch (const std::exception& e) { std::cerr << e.what() << '\n'; captureFailed = true; }
        capture.drainMarkers = {};
        close(markerSockets[0]);
        scope_bpf__detach(skel.get());
        for (;;) {
            int result = ring_buffer__consume(ring.get());
            if (result == 0) break;
            if (result < 0) { captureFailed = true; break; }
        }

        captureStats stats{};
        if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.capture_stats), &key, &stats) != 0)
            captureFailed = true;
        RecordingQuality quality;
        quality.events = writer->count();
        quality.dropped_events = stats.dropped_events;
        quality.tracking_failures = stats.tracking_failures;
        quality.stack_failures = stats.stack_failures;
        quality.available = true;
        quality.complete = childExited && !stopRequested && !captureFailed &&
                           !stats.dropped_events && !stats.tracking_failures;
        writer->finish(quality);

        // Recording ownership restored to the sudo caller
        if (chown("recording.scope", identity.uid, identity.gid) != 0)
            std::cerr << "Warning: recording.scope is owned by root\n";
        std::cout << "Saved recording.scope (" << writer->count() << " events, "
                  << stats.dropped_events << " dropped, "
                  << stats.stack_failures << " stack failures, "
                  << (quality.complete ? "complete" : "incomplete") << ")\n";
        if (captureFailed) return 1;
        if (stopRequested) return 130;
        if (childExited && WIFEXITED(status)) return WEXITSTATUS(status);
        if (childExited && WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Scope: " << e.what() << '\n';
        return 1;
    }
}
