#include <iostream>
#include <string>
#include <cstring>
#include <cstdio>
#include <csignal>
#include <cerrno>
#include <cstdlib>
#include <charconv>
#include <vector>
#include <variant>
#include <grp.h>
#include <pwd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "events.h"
#include "recording.hpp"

#include "scope.skel.h"

volatile std::sig_atomic_t stopRequested = 0;
static unsigned long long eventCount = 0;

using traceEvent = std::variant<
    schedEvent,
    wakeEvent,
    forkEvent,
    exitEvent
>;

struct Recording {
    std::vector<traceEvent> events;
};

static int handle_event(void* ctx, void* data, size_t data_sz) {

    auto* recording = static_cast<Recording*>(ctx);

    if (data_sz < sizeof(eventHeader)) {
        std::cerr << "Event is too small" << std::endl;
        return -EINVAL;
    }

    eventHeader header{};
    std::memcpy(&header, data, sizeof(header));
    ++eventCount;

    auto storeEvent = [&]<typename T>() -> int {
        if (data_sz != sizeof(T)) {
            std::cerr << "Error: Unexpected record size recieved! "
                    << "Expected " << sizeof(T) << "bytes, "
                    << "but got " << data_sz << " bytes." << std::endl;
            return -EINVAL;
        }
        T event{};
        std::memcpy(&event, data, sizeof(T));
        if (recording->events.size() >= recording->events.capacity()) {
            return -ENOSPC;
        }
        recording->events.emplace_back(event);

        return 0;
    };

    switch (header.type) {
        case EVENT_SWITCH: {
            storeEvent.operator()<schedEvent>();
        }

        case EVENT_WAKING:
        case EVENT_WAKEUP: {
            storeEvent.operator()<wakeEvent>();
        }
        case EVENT_FORK: {
            storeEvent.operator()<forkEvent>();
        }
        case EVENT_EXIT: {
            storeEvent.operator()<exitEvent>();
        }


        default: {
            std::cerr << "Error: Unexpected record type recieved! " << std::endl;
            return -EINVAL;
        }
    }
}

void handleSignInt(int signal) {
    if (signal == SIGINT) {
        stopRequested = 1;
    }
}

int main(int argc, char* argv[]) {
    // parsing
    if (argc < 4 || 
        std::strcmp(argv[1],"run") != 0 || 
        std::strcmp(argv[2],"--") != 0) {
        std::cerr << "Usage: scope run -- <command> [arguments...]" << std::endl;
        return 1;
    }


    if( geteuid() != 0 ) {
        std::cerr << "UserID Failure" << std::endl;
        return 1;
    }

    if (std::signal(SIGINT, handleSignInt) == SIG_ERR) {
        std::cerr << "Failed to register signal handler" << std::endl;
        return 1;
    }
    struct scope_bpf* skel = scope_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to load BPF program" << std::endl;
        return 1;
    }

    Recording recording;
    recording.events.reserve(200'000);

    struct ring_buffer* rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        &recording,
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

    // make sure child dosen't execute stuff with sudo

    const char* uidText = std::getenv("SUDO_UID");
    const char* gidText = std::getenv("SUDO_GID");
    if (!uidText || !gidText) {
        std::cerr << "Scope requires a valid sudo user identity" << std::endl;
        ring_buffer__free(rb);
        scope_bpf__destroy(skel);
        return 1;
    }

    uid_t targetUid = 0;
    const char* end = uidText + std::strlen(uidText);
    auto [ptr, ec] = std::from_chars(uidText, end, targetUid);
    if (ptr != end || ec != std::errc{} || targetUid < 1) {
        ring_buffer__free(rb);
        scope_bpf__destroy(skel);
        std::cerr << "Error UID Parsing" << std::endl;
        return 1;
    }

    passwd* user = getpwuid(targetUid);
    if (!user || !user->pw_name) {
        ring_buffer__free(rb);
        scope_bpf__destroy(skel);
        std::cerr << "Could not find target user" << std::endl;
        return 1;    
    }

    std::string username = user->pw_name;

    gid_t targetGid = 0;
    const char* end2 = gidText + std::strlen(gidText);
    auto [ptr2, ec2] = std::from_chars(gidText, end2, targetGid);
    if (ptr2 != end2 || ec2 != std::errc{} || targetGid < 1) {
        ring_buffer__free(rb);
        scope_bpf__destroy(skel);
        std::cerr << "Error GID Parsing" << std::endl;
        return 1;
    }

    // launch child process 
    int syncPipe[2];

    if (pipe2(syncPipe, O_CLOEXEC) == -1) {
        ring_buffer__free(rb);
        scope_bpf__destroy(skel);
        std::cerr << "Failed to create synchronization pipe" << std::endl;
        return 1;
    }

    pid_t child = fork();
    if ( child == 0 ) { // child
        close(syncPipe[1]);
        char message = 0;
        ssize_t n;

        do {
            n = read(syncPipe[0], &message, 1);
        } while (n == -1 && errno == EINTR);
        close(syncPipe[0]);

        // only continue if the parent released us
        if (n != 1 || message != 'R') {
            _exit(126);
        }

        // restore the original user's groups
        if (initgroups(username.c_str(), targetGid) == -1) {
            _exit(126);
        }

        // drop root group privileges
        if (setresgid(targetGid, targetGid, targetGid) == -1) {
            _exit(126);
        }

        // drop root user privileges
        if (setresuid(targetUid, targetUid, targetUid) == -1) {
            _exit(126);
        }

        // run the requested program
        execvp(argv[3], &argv[3]);

        // only reached if execvp fails
        _exit(127);
    } else if( child < 0 ) { // error
        std::cerr << "Failed to create child" << std::endl;
        close(syncPipe[0]);
        close(syncPipe[1]);
        ring_buffer__free(rb);
        scope_bpf__destroy(skel);
        return 1;
    } else { // parent
        close(syncPipe[0]);
        if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
            std::cerr << "Failed to track child" << std::endl;
            
            close(syncPipe[1]);

            int status;
            while (waitpid(child, &status, 0) == -1 && errno == EINTR) {
            }            
            
            ring_buffer__free(rb);
            scope_bpf__destroy(skel);
            return 1;
        }
        // setup tracking

        uint32_t tid = static_cast<uint32_t>(child);
        uint8_t value = 1;

        int mapFd = bpf_map__fd(skel->maps.tracked_tids);

        int result = bpf_map_update_elem(
            mapFd,
            &tid,
            &value,
            BPF_ANY
        );
        if (result < 0) {
            std::cerr << "Failed to track child" << std::endl;
            
            close(syncPipe[1]);

            int status;
            while (waitpid(child, &status, 0) == -1 && errno == EINTR) {
            }            
            
            ring_buffer__free(rb);
            scope_bpf__destroy(skel);
            return 1;
        }

        char message = 'R';
        ssize_t n = write(syncPipe[1], &message, 1);
        close(syncPipe[1]);

        if (n != 1) {
            std::cerr << "Failed to release child\n";

            int status = 0;
            pid_t waited;

            do {
                waited = waitpid(child, &status, 0);
            } while (waited == -1 && errno == EINTR);

            if (waited == -1) {
                std::cerr << "Failed to reap child: "
                        << std::strerror(errno) << std::endl;
            }

            ring_buffer__free(rb);
            scope_bpf__destroy(skel);
            return 1;
        }
    }

    int exitCode = 0;
    int childStatus = 0;
    bool childExited = false;
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

        pid_t finished = waitpid(child, &childStatus, WNOHANG);
        if (finished == child) {
            childExited = true;
            break;
        }
        if (finished == -1) {
            if (errno == EINTR) {
                continue;
            }

            std::cerr << "waitpid failed: "
                    << std::strerror(errno) << std::endl;
            exitCode = 1;
            break;
        }
    }
    if (!childExited) {
        if (kill(child, SIGKILL) == -1 && errno != ESRCH) {
            std::cerr << "Failed to terminate child: "
                    << std::strerror(errno) << std::endl;
            exitCode = 1;
        }

        while (true) {
            pid_t waited = waitpid(child, &childStatus, 0);

            if (waited == child) {
                childExited = true;
                break;
            }

            if (waited == -1 && errno == EINTR) {
                continue;
            }

            std::cerr << "Failed to reap child: "
                    << std::strerror(errno) << std::endl;
            exitCode = 1;
            break;
        }
    }
    scope_bpf__detach(skel);

    int drained = ring_buffer__consume(rb);

    if (drained < 0) {
        std::cerr << "Failed to drain ring buffer: "
                << drained << std::endl;
        exitCode = 1;
    }

    try {
        saveRecording("recording.scope", recording.events);
        std::cout << "Saved recording.scope\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to save recording: "
                << e.what() << '\n';
        exitCode = 1;
    }

    if (childExited && exitCode == 0) {
        if (WIFEXITED(childStatus)) {
            exitCode = WEXITSTATUS(childStatus);
            std::cout << "Child exited with code "
                    << exitCode << std::endl;
        } else if (WIFSIGNALED(childStatus)) {
            int signal = WTERMSIG(childStatus);
            std::cout << "Child terminated by signal "
                    << signal << std::endl;
            exitCode = 128 + signal;
        }
    }

    std::cout << "Events received: " << eventCount << std::endl;

    ring_buffer__free(rb);
    scope_bpf__destroy(skel);

    return exitCode;

}