#include "recording.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>

int main() {
    const auto path = (std::filesystem::temp_directory_path() / "scope_v2_roundtrip_test.scope").string();
    std::filesystem::remove(path);
    try {
        {
            RecordingWriter writer(path);
            schedEvent sw{};
            sw.header.type = EVENT_SWITCH;
            sw.header.timestamp_ns = 100;
            sw.prev_tid = 42; sw.next_tid = 43; sw.stack_id = 17;
            sw.process_pid = 456;
            wakeEvent w{};
            w.header.type = EVENT_WAKING; w.header.timestamp_ns = 200;
            w.target_tid = 43; w.current_tid = 42; w.stack_id = 17;
            w.process_pid = 456;
            forkEvent f{};
            f.header.type = EVENT_FORK; f.header.timestamp_ns = 300;
            f.parent_tid = 42; f.child_tid = 44;
            exitEvent x{};
            x.header.type = EVENT_EXIT; x.header.timestamp_ns = 400; x.tid = 44;
            for (int i = 0; i < 4000; ++i) {
                sw.header.timestamp_ns = 100 + i;
                writer.append(sw);
            }
            writer.append(w); writer.append(f); writer.append(x);
            std::array<std::uint64_t,16> pcs{};
            pcs[0] = 0x1234;
            pcs[1] = 0x5678;
            writer.storeStack(17, pcs);
            ExecutableMapping m{};
            m.process_pid = 456;
            m.observed_ns = 150;
            m.start = 0x70000000;
            m.end = 0x70001000;
            m.file_offset = 0x1000;
            m.inode = 123;
            m.device = 42;
            m.modified_ns = 314159;
            m.path = "/tmp/build/stress";
            writer.storeMappings({m});
            RecordingQuality q;
            q.dropped_events = 2; q.stack_failures = 3; q.complete = false;
            writer.finish(q);
        }
        auto events = loadRecording(path);
        auto q = loadRecordingQuality(path);
        auto frames = loadStack(path, 17);
        auto maps = loadMappings(path);
        if (events.size() != 4003 || q.complete || q.dropped_events != 2 ||
            q.stack_failures != 3 || frames.size() != 2 || frames[1] != 0x5678 ||
            maps.size() != 1 || maps[0].process_pid != 456 ||
            maps[0].start != 0x70000000 || maps[0].path != "/tmp/build/stress")
            throw std::runtime_error("roundtrip mismatch");
        if (std::get<schedEvent>(events[0]).stack_id != 17 ||
            std::get<schedEvent>(events[0]).process_pid != 456 ||
            std::get<wakeEvent>(events[4000]).stack_id != 17 ||
            std::get<wakeEvent>(events[4000]).process_pid != 456)
            throw std::runtime_error("stack id mismatch");
        if (std::get<forkEvent>(events[4001]).child_tid != 44 ||
            std::get<exitEvent>(events[4002]).tid != 44)
            throw std::runtime_error("lifecycle mismatch");
        std::filesystem::remove(path);
        std::cout << "PASS: 4,003 streamed records, stacks, source mappings, quality, and all event types\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
