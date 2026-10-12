#include "recording.hpp"

#include <sqlite3.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <type_traits>
#include <initializer_list>
#include <limits>

namespace {
std::runtime_error sqlError(sqlite3* db) {
    return std::runtime_error(db ? sqlite3_errmsg(db) : "SQLite allocation failure");
}

struct Reader {
    sqlite3* db = nullptr;
    sqlite3_stmt* stmt = nullptr;
    explicit Reader(const std::string& path) {
        if (sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
            auto message = sqlError(db);
            sqlite3_close(db);
            db = nullptr;
            throw message;
        }
    }
    ~Reader() { sqlite3_finalize(stmt); sqlite3_close(db); }
    void prepare(const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
            throw sqlError(db);
    }
};

int schemaVersion(sqlite3* db) {
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &s, nullptr) != SQLITE_OK)
        throw sqlError(db);
    const int rc = sqlite3_step(s);
    const int version = (rc == SQLITE_ROW) ? sqlite3_column_int(s, 0) : -1;
    sqlite3_finalize(s);
    if (version != 1 && version != 2 && version != 3 && version != 4) throw std::runtime_error("Unsupported .scope schema version");
    return version;
}
} // namespace

void RecordingWriter::exec(const char* sql) {
    if (sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw sqlError(db_);
}

RecordingWriter::RecordingWriter(const std::string& path) {
    if (std::filesystem::exists(path))
        throw std::runtime_error("Recording already exists: " + path);
    if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
        auto message = sqlError(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw message;
    }
    try {
        exec("PRAGMA journal_mode=DELETE;");
        exec("PRAGMA synchronous=NORMAL;");
        exec(R"SQL(
            CREATE TABLE events (
                seq INTEGER PRIMARY KEY,
                type INTEGER NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                prev_tid INTEGER, next_tid INTEGER, prev_state INTEGER, cpu INTEGER,
                target_tid INTEGER, current_tid INTEGER, target_cpu INTEGER,
                parent_tid INTEGER, child_tid INTEGER, tid INTEGER,
                stack_id INTEGER, process_pid INTEGER,
                prev_comm TEXT, next_comm TEXT, namespace_tid INTEGER,
                span_id INTEGER, span_phase INTEGER, span_name TEXT
            );
            CREATE TABLE stacks (id INTEGER PRIMARY KEY, pcs BLOB NOT NULL);
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
            CREATE TABLE executable_maps (
                process_pid INTEGER NOT NULL, observed_ns INTEGER NOT NULL,
                start INTEGER NOT NULL, end INTEGER NOT NULL, file_offset INTEGER NOT NULL,
                inode INTEGER NOT NULL, device INTEGER NOT NULL,
                modified_ns INTEGER NOT NULL, path TEXT NOT NULL
            );
            CREATE INDEX idx_maps_process_time ON executable_maps(process_pid,observed_ns);
            CREATE INDEX idx_events_time ON events(timestamp_ns);
            PRAGMA user_version=4;
        )SQL");
        const char* insert = R"SQL(
            INSERT INTO events(type,timestamp_ns,prev_tid,next_tid,prev_state,cpu,
                               target_tid,current_tid,target_cpu,parent_tid,child_tid,tid,stack_id,process_pid,
                               prev_comm,next_comm,namespace_tid,span_id,span_phase,span_name)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
        )SQL";
        if (sqlite3_prepare_v2(db_, insert, -1, &eventStmt_, nullptr) != SQLITE_OK)
            throw sqlError(db_);
        if (sqlite3_prepare_v2(db_, "INSERT OR IGNORE INTO stacks(id,pcs) VALUES (?,?);",
                               -1, &stackStmt_, nullptr) != SQLITE_OK)
            throw sqlError(db_);
        if (sqlite3_prepare_v2(db_,
            "INSERT INTO executable_maps(process_pid,observed_ns,start,end,file_offset,inode,device,modified_ns,path) "
            "VALUES (?,?,?,?,?,?,?,?,?);", -1, &mappingStmt_, nullptr) != SQLITE_OK)
            throw sqlError(db_);
        exec("BEGIN IMMEDIATE;");
    } catch (...) {
        sqlite3_finalize(eventStmt_);
        sqlite3_finalize(stackStmt_);
        sqlite3_finalize(mappingStmt_);
        sqlite3_close(db_);
        db_ = nullptr;
        eventStmt_ = stackStmt_ = nullptr;
        throw;
    }
}

RecordingWriter::~RecordingWriter() {
    if (db_) {
        if (!finished_) sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_finalize(eventStmt_);
        sqlite3_finalize(stackStmt_);
        sqlite3_finalize(mappingStmt_);
        sqlite3_close(db_);
    }
}

void RecordingWriter::commitBatch() {
    if (sinceCommit_ < 2048) return;
    exec("COMMIT;");
    exec("BEGIN IMMEDIATE;");
    sinceCommit_ = 0;
}

void RecordingWriter::append(const traceEvent& event) {
    if (finished_) throw std::runtime_error("Recording already finalized");
    if (sqlite3_reset(eventStmt_) != SQLITE_OK ||
        sqlite3_clear_bindings(eventStmt_) != SQLITE_OK) throw sqlError(db_);
    auto check = [this](int result) {
        if (result != SQLITE_OK) throw sqlError(db_);
    };
    std::visit([&](const auto& e) {
        using T = std::decay_t<decltype(e)>;
        if (e.header.timestamp_ns > static_cast<std::uint64_t>(std::numeric_limits<sqlite3_int64>::max()))
            throw std::runtime_error("Timestamp is outside SQLite integer range");
        check(sqlite3_bind_int(eventStmt_, 1, e.header.type));
        check(sqlite3_bind_int64(eventStmt_, 2, static_cast<sqlite3_int64>(e.header.timestamp_ns)));
        if constexpr (std::is_same_v<T, schedEvent>) {
            check(sqlite3_bind_int(eventStmt_, 3, e.prev_tid));
            check(sqlite3_bind_int(eventStmt_, 4, e.next_tid));
            check(sqlite3_bind_int64(eventStmt_, 5, e.prev_state));
            check(sqlite3_bind_int(eventStmt_, 6, e.cpu));
            check(sqlite3_bind_int(eventStmt_, 13, e.stack_id));
            check(sqlite3_bind_int(eventStmt_, 14, e.process_pid));
            check(sqlite3_bind_text(eventStmt_, 15, e.prev_comm, strnlen(e.prev_comm, 16), SQLITE_TRANSIENT));
            check(sqlite3_bind_text(eventStmt_, 16, e.next_comm, strnlen(e.next_comm, 16), SQLITE_TRANSIENT));
            check(sqlite3_bind_int(eventStmt_, 17, e.namespace_tid));
        } else if constexpr (std::is_same_v<T, wakeEvent>) {
            check(sqlite3_bind_int(eventStmt_, 6, e.cpu));
            check(sqlite3_bind_int(eventStmt_, 7, e.target_tid));
            check(sqlite3_bind_int(eventStmt_, 8, e.current_tid));
            check(sqlite3_bind_int(eventStmt_, 9, e.target_cpu));
            check(sqlite3_bind_int(eventStmt_, 13, e.stack_id));
            check(sqlite3_bind_int(eventStmt_, 14, e.process_pid));
        } else if constexpr (std::is_same_v<T, forkEvent>) {
            check(sqlite3_bind_int(eventStmt_, 10, e.parent_tid));
            check(sqlite3_bind_int(eventStmt_, 11, e.child_tid));
        } else if constexpr (std::is_same_v<T, exitEvent>) {
            check(sqlite3_bind_int(eventStmt_, 12, e.tid));
        } else if constexpr (std::is_same_v<T, spanEvent>) {
            check(sqlite3_bind_int64(eventStmt_, 18, static_cast<sqlite3_int64>(e.span_id)));
            check(sqlite3_bind_int(eventStmt_, 19, e.phase));
            check(sqlite3_bind_int(eventStmt_, 17, e.namespace_tid));
            check(sqlite3_bind_text(eventStmt_, 20, e.name, strnlen(e.name, sizeof(e.name)), SQLITE_TRANSIENT));
        }
    }, event);
    if (sqlite3_step(eventStmt_) != SQLITE_DONE) throw sqlError(db_);
    ++count_;
    ++sinceCommit_;
    commitBatch();
}

void RecordingWriter::storeStack(std::int32_t id, const std::array<std::uint64_t, 16>& pcs) {
    if (id < 0 || finished_) return;
    if (sqlite3_reset(stackStmt_) != SQLITE_OK ||
        sqlite3_clear_bindings(stackStmt_) != SQLITE_OK) throw sqlError(db_);
    if (sqlite3_bind_int(stackStmt_, 1, id) != SQLITE_OK ||
        sqlite3_bind_blob(stackStmt_, 2, pcs.data(), static_cast<int>(sizeof(pcs)), SQLITE_TRANSIENT) != SQLITE_OK)
        throw sqlError(db_);
    if (sqlite3_step(stackStmt_) != SQLITE_DONE) throw sqlError(db_);
}

void RecordingWriter::storeMappings(const std::vector<ExecutableMapping>& maps) {
    for (const auto& m : maps) {
        if (finished_) throw std::runtime_error("Recording already finalized");
        if (sqlite3_reset(mappingStmt_) != SQLITE_OK ||
            sqlite3_clear_bindings(mappingStmt_) != SQLITE_OK) throw sqlError(db_);
        auto bind = [this](int code) { if (code != SQLITE_OK) throw sqlError(db_); };
        bind(sqlite3_bind_int(mappingStmt_, 1, m.process_pid));
        bind(sqlite3_bind_int64(mappingStmt_, 2, static_cast<sqlite3_int64>(m.observed_ns)));
        bind(sqlite3_bind_int64(mappingStmt_, 3, static_cast<sqlite3_int64>(m.start)));
        bind(sqlite3_bind_int64(mappingStmt_, 4, static_cast<sqlite3_int64>(m.end)));
        bind(sqlite3_bind_int64(mappingStmt_, 5, static_cast<sqlite3_int64>(m.file_offset)));
        bind(sqlite3_bind_int64(mappingStmt_, 6, static_cast<sqlite3_int64>(m.inode)));
        bind(sqlite3_bind_int64(mappingStmt_, 7, static_cast<sqlite3_int64>(m.device)));
        bind(sqlite3_bind_int64(mappingStmt_, 8, m.modified_ns));
        bind(sqlite3_bind_text(mappingStmt_, 9, m.path.c_str(), -1, SQLITE_TRANSIENT));
        if (sqlite3_step(mappingStmt_) != SQLITE_DONE) throw sqlError(db_);
        ++sinceCommit_;
        commitBatch();
    }
}

void RecordingWriter::finish(const RecordingQuality& quality) {
    if (finished_) return;
    auto meta = [&](const char* key, std::uint64_t value) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, "INSERT INTO metadata(key,value) VALUES (?,?);", -1, &stmt, nullptr)
            != SQLITE_OK) throw sqlError(db_);
        const bool ok = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(value)) == SQLITE_OK &&
            sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        if (!ok) throw sqlError(db_);
    };
    meta("events", count_);
    meta("dropped_events", quality.dropped_events);
    meta("tracking_failures", quality.tracking_failures);
    meta("stack_failures", quality.stack_failures);
    meta("complete", quality.complete ? 1 : 0);
    exec("COMMIT;");
    finished_ = true;
}

void saveRecording(const std::string& path, const std::vector<traceEvent>& events) {
    RecordingWriter writer(path);
    for (const auto& e : events) writer.append(e);
    RecordingQuality quality;
    quality.complete = true;
    writer.finish(quality);
}

std::vector<traceEvent> loadRecording(const std::string& path) {
    Reader r(path);
    const int version = schemaVersion(r.db);
    r.prepare(version == 4 ? R"SQL(
        SELECT type,timestamp_ns,prev_tid,next_tid,prev_state,cpu,
               target_tid,current_tid,target_cpu,parent_tid,child_tid,tid,stack_id,process_pid,
               prev_comm,next_comm,namespace_tid,span_id,span_phase,span_name
        FROM events ORDER BY seq;
    )SQL" : version == 3 ? R"SQL(
        SELECT type,timestamp_ns,prev_tid,next_tid,prev_state,cpu,
               target_tid,current_tid,target_cpu,parent_tid,child_tid,tid,stack_id,process_pid
        FROM events ORDER BY seq;
    )SQL" : version == 2 ? R"SQL(
        SELECT type,timestamp_ns,prev_tid,next_tid,prev_state,cpu,
               target_tid,current_tid,target_cpu,parent_tid,child_tid,tid,stack_id,NULL
        FROM events ORDER BY seq;
    )SQL" : R"SQL(
        SELECT type,timestamp_ns,prev_tid,next_tid,prev_state,cpu,
               target_tid,current_tid,target_cpu,parent_tid,child_tid,tid,NULL,NULL
        FROM events ORDER BY seq;
    )SQL");
    std::vector<traceEvent> events;
    int result = SQLITE_OK;
    auto required = [&](std::initializer_list<int> cols) {
        for (int column : cols)
            if (sqlite3_column_type(r.stmt, column) == SQLITE_NULL)
                throw std::runtime_error("Recording has a missing event field");
    };
    while ((result = sqlite3_step(r.stmt)) == SQLITE_ROW) {
        required({0,1});
        const int type = sqlite3_column_int(r.stmt, 0);
        const sqlite3_int64 signedTimestamp = sqlite3_column_int64(r.stmt, 1);
        if (signedTimestamp < 0) throw std::runtime_error("Invalid timestamp");
        const auto timestamp = static_cast<std::uint64_t>(signedTimestamp);
        switch (type) {
            case EVENT_SWITCH: {
                required({2,3,4,5});
                schedEvent e{};
                e.header.type = type;
                e.header.timestamp_ns = timestamp;
                e.prev_tid = sqlite3_column_int(r.stmt, 2);
                e.next_tid = sqlite3_column_int(r.stmt, 3);
                e.prev_state = sqlite3_column_int64(r.stmt, 4);
                e.cpu = sqlite3_column_int(r.stmt, 5);
                e.stack_id = version >= 2 && sqlite3_column_type(r.stmt,12) != SQLITE_NULL
                    ? sqlite3_column_int(r.stmt, 12) : -1;
                e.process_pid = version >= 3 && sqlite3_column_type(r.stmt,13) != SQLITE_NULL ? sqlite3_column_int(r.stmt,13) : -1;
                if (version >= 4) {
                    auto copyName = [&](int column, char* target) {
                        const auto* text = sqlite3_column_text(r.stmt, column);
                        if (text) std::strncpy(target, reinterpret_cast<const char*>(text), 15);
                    };
                    copyName(14, e.prev_comm);
                    copyName(15, e.next_comm);
                    e.namespace_tid = sqlite3_column_type(r.stmt,16) == SQLITE_NULL ? -1 : sqlite3_column_int(r.stmt,16);
                } else e.namespace_tid = -1;
                events.emplace_back(e);
                break;
            }
            case EVENT_WAKING: case EVENT_WAKEUP: case EVENT_WAKEUP_NEW: {
                required({5,6,7,8});
                wakeEvent e{};
                e.header.type = type;
                e.header.timestamp_ns = timestamp;
                e.cpu = sqlite3_column_int(r.stmt, 5);
                e.target_tid = sqlite3_column_int(r.stmt, 6);
                e.current_tid = sqlite3_column_int(r.stmt, 7);
                e.target_cpu = sqlite3_column_int(r.stmt, 8);
                e.stack_id = version >= 2 && sqlite3_column_type(r.stmt,12) != SQLITE_NULL
                    ? sqlite3_column_int(r.stmt, 12) : -1;
                e.process_pid = version >= 3 && sqlite3_column_type(r.stmt,13) != SQLITE_NULL ? sqlite3_column_int(r.stmt,13) : -1;
                events.emplace_back(e);
                break;
            }
            case EVENT_FORK: {
                required({9,10});
                forkEvent e{}; e.header.type=type; e.header.timestamp_ns=timestamp;
                e.parent_tid=sqlite3_column_int(r.stmt,9);
                e.child_tid=sqlite3_column_int(r.stmt,10);
                events.emplace_back(e);
                break;
            }
            case EVENT_EXIT: {
                required({11});
                exitEvent e{}; e.header.type=type; e.header.timestamp_ns=timestamp;
                e.tid=sqlite3_column_int(r.stmt,11);
                events.emplace_back(e);
                break;
            }
            case EVENT_SPAN: {
                if (version < 4) throw std::runtime_error("Unexpected span in old recording");
                required({16,17,18,19});
                spanEvent e{};
                e.header.type = type;
                e.header.timestamp_ns = timestamp;
                e.namespace_tid = sqlite3_column_int(r.stmt,16);
                e.span_id = static_cast<scope_u64>(sqlite3_column_int64(r.stmt,17));
                e.phase = static_cast<scope_u32>(sqlite3_column_int(r.stmt,18));
                const auto* name = sqlite3_column_text(r.stmt,19);
                if (name) std::strncpy(e.name, reinterpret_cast<const char*>(name), sizeof(e.name)-1);
                if (e.phase != 1 && e.phase != 2) throw std::runtime_error("Invalid span phase");
                events.emplace_back(e);
                break;
            }
            default: throw std::runtime_error("Unknown event type in recording");
        }
    }
    if (result != SQLITE_DONE) throw sqlError(r.db);
    return events;
}

RecordingQuality loadRecordingQuality(const std::string& path) {
    Reader r(path);
    if (schemaVersion(r.db) == 1) return {};
    RecordingQuality quality;
    quality.available = true;
    r.prepare("SELECT key,value FROM metadata;");
    int result = SQLITE_OK;
    while ((result = sqlite3_step(r.stmt)) == SQLITE_ROW) {
        const char* key = reinterpret_cast<const char*>(sqlite3_column_text(r.stmt, 0));
        if (!key) continue;
        const auto value = static_cast<std::uint64_t>(sqlite3_column_int64(r.stmt, 1));
        const std::string name(key);
        if (name == "events") quality.events = value;
        else if (name == "dropped_events") quality.dropped_events = value;
        else if (name == "tracking_failures") quality.tracking_failures = value;
        else if (name == "stack_failures") quality.stack_failures = value;
        else if (name == "complete") quality.complete = (value != 0);
    }
    if (result != SQLITE_DONE) throw sqlError(r.db);
    return quality;
}

std::vector<std::uint64_t> loadStack(const std::string& path, std::int32_t id) {
    if (id < 0) return {};
    Reader r(path);
    if (schemaVersion(r.db) == 1) return {};
    r.prepare("SELECT pcs FROM stacks WHERE id=?;");
    if (sqlite3_bind_int(r.stmt, 1, id) != SQLITE_OK) throw sqlError(r.db);
    const int rc = sqlite3_step(r.stmt);
    if (rc == SQLITE_DONE) return {};
    if (rc != SQLITE_ROW) throw sqlError(r.db);
    if (sqlite3_column_bytes(r.stmt, 0) != 16 * static_cast<int>(sizeof(std::uint64_t)))
        throw std::runtime_error("Invalid stack payload");
    std::array<std::uint64_t,16> pcs{};
    std::memcpy(pcs.data(), sqlite3_column_blob(r.stmt, 0), sizeof(pcs));
    std::vector<std::uint64_t> result;
    for (auto pc : pcs) if (pc) result.push_back(pc);
    return result;
}

std::vector<ExecutableMapping> loadMappings(const std::string& path) {
    Reader r(path);
    if (schemaVersion(r.db) < 3) return {};
    r.prepare("SELECT process_pid,observed_ns,start,end,file_offset,inode,device,modified_ns,path "
              "FROM executable_maps ORDER BY observed_ns;");
    std::vector<ExecutableMapping> maps;
    int result;
    while ((result = sqlite3_step(r.stmt)) == SQLITE_ROW) {
        ExecutableMapping m;
        m.process_pid = sqlite3_column_int(r.stmt, 0);
        m.observed_ns = static_cast<std::uint64_t>(sqlite3_column_int64(r.stmt, 1));
        m.start = static_cast<std::uint64_t>(sqlite3_column_int64(r.stmt, 2));
        m.end = static_cast<std::uint64_t>(sqlite3_column_int64(r.stmt, 3));
        m.file_offset = static_cast<std::uint64_t>(sqlite3_column_int64(r.stmt, 4));
        m.inode = static_cast<std::uint64_t>(sqlite3_column_int64(r.stmt, 5));
        m.device = static_cast<std::uint64_t>(sqlite3_column_int64(r.stmt, 6));
        m.modified_ns = sqlite3_column_int64(r.stmt, 7);
        const auto* name = sqlite3_column_text(r.stmt, 8);
        if (name) m.path = reinterpret_cast<const char*>(name);
        maps.push_back(std::move(m));
    }
    if (result != SQLITE_DONE) throw sqlError(r.db);
    return maps;
}
