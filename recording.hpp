#pragma once

#include "reconstruct.hpp"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

// One executable mapping observed while the command was running.
// These are snapshots, not an authoritative memory-map history.
struct ExecutableMapping {
    std::int32_t process_pid = -1;
    std::uint64_t observed_ns = 0;
    std::uint64_t start = 0, end = 0, file_offset = 0;
    std::uint64_t inode = 0, device = 0;
    std::int64_t modified_ns = 0;
    std::string path;
};

struct sqlite3;
struct sqlite3_stmt;

struct RecordingQuality {
    std::uint64_t events = 0;
    std::uint64_t dropped_events = 0;
    std::uint64_t tracking_failures = 0;
    std::uint64_t stack_failures = 0;
    bool complete = false;
    bool available = false; // legacy v1 files have no quality report
};

// Append directly to SQLite: no arbitrary 200,000-event RAM limit.
class RecordingWriter {
public:
    explicit RecordingWriter(const std::string& path);
    ~RecordingWriter();
    RecordingWriter(const RecordingWriter&) = delete;
    RecordingWriter& operator=(const RecordingWriter&) = delete;

    void append(const traceEvent& event);
    void storeStack(std::int32_t id, const std::array<std::uint64_t, 16>& pcs);
    void storeMappings(const std::vector<ExecutableMapping>& maps);
    void finish(const RecordingQuality& quality);
    std::uint64_t count() const { return count_; }

private:
    sqlite3* db_ = nullptr;
    sqlite3_stmt* eventStmt_ = nullptr;
    sqlite3_stmt* stackStmt_ = nullptr;
    sqlite3_stmt* mappingStmt_ = nullptr;
    std::uint64_t count_ = 0;
    std::uint64_t sinceCommit_ = 0;
    bool finished_ = false;
    void exec(const char* sql);
    void commitBatch();
};

void saveRecording(const std::string& path, const std::vector<traceEvent>& events);
std::vector<traceEvent> loadRecording(const std::string& path);
RecordingQuality loadRecordingQuality(const std::string& path);
std::vector<std::uint64_t> loadStack(const std::string& path, std::int32_t id);

std::vector<ExecutableMapping> loadMappings(const std::string& path);
