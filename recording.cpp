#include "recording.hpp"

#include <sqlite3.h>
#include <stdexcept>
#include <type_traits>

void saveRecording(
    const std::string& path,
    const std::vector<traceEvent>& events
) {
    sqlite3* db = nullptr;

    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        std::string error = db ? sqlite3_errmsg(db) : "Cannot open database";
        sqlite3_close(db);
        throw std::runtime_error(error);
    }

    sqlite3_stmt* stmt = nullptr;
    bool transactionStarted = false;

    try {
        auto executeSQL = [&](const char* sql) {
            if (sqlite3_exec(db, sql, nullptr, nullptr, nullptr) != SQLITE_OK) {
                throw std::runtime_error(sqlite3_errmsg(db));
            }
        };

        executeSQL("BEGIN TRANSACTION;");
        transactionStarted = true;

        executeSQL(R"(
            CREATE TABLE events (
                seq INTEGER PRIMARY KEY,
                type INTEGER NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                prev_tid INTEGER,
                next_tid INTEGER,
                prev_state INTEGER,
                cpu INTEGER,
                target_tid INTEGER,
                current_tid INTEGER,
                target_cpu INTEGER,
                parent_tid INTEGER,
                child_tid INTEGER,
                tid INTEGER
            );
        )");

        executeSQL("PRAGMA user_version = 1;");

        const char* insertSQL = R"(
            INSERT INTO events (
                type, timestamp_ns,
                prev_tid, next_tid, prev_state, cpu,
                target_tid, current_tid, target_cpu,
                parent_tid, child_tid, tid
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        )";

        if (sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db));
        }

        auto checkBind = [&](int result) {
            if (result != SQLITE_OK) {
                throw std::runtime_error(sqlite3_errmsg(db));
            }
        };

        for (const auto& event : events) {
            if (sqlite3_reset(stmt) != SQLITE_OK ||
                sqlite3_clear_bindings(stmt) != SQLITE_OK) {
                throw std::runtime_error(sqlite3_errmsg(db));
            }

            std::visit([&](const auto& e) {
                using T = std::decay_t<decltype(e)>;

                checkBind(sqlite3_bind_int(stmt, 1, e.header.type));
                checkBind(sqlite3_bind_int64(stmt, 2, e.header.timestamp_ns));

                if constexpr (std::is_same_v<T, schedEvent>) {
                    checkBind(sqlite3_bind_int(stmt, 3, e.prev_tid));
                    checkBind(sqlite3_bind_int(stmt, 4, e.next_tid));
                    checkBind(sqlite3_bind_int64(stmt, 5, e.prev_state));
                    checkBind(sqlite3_bind_int(stmt, 6, e.cpu));
                }
                else if constexpr (std::is_same_v<T, wakeEvent>) {
                    checkBind(sqlite3_bind_int(stmt, 6, e.cpu));
                    checkBind(sqlite3_bind_int(stmt, 7, e.target_tid));
                    checkBind(sqlite3_bind_int(stmt, 8, e.current_tid));
                    checkBind(sqlite3_bind_int(stmt, 9, e.target_cpu));
                }
                else if constexpr (std::is_same_v<T, forkEvent>) {
                    checkBind(sqlite3_bind_int(stmt, 10, e.parent_tid));
                    checkBind(sqlite3_bind_int(stmt, 11, e.child_tid));
                }
                else if constexpr (std::is_same_v<T, exitEvent>) {
                    checkBind(sqlite3_bind_int(stmt, 12, e.tid));
                }
            }, event);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                throw std::runtime_error(sqlite3_errmsg(db));
            }
        }

        int finalizeResult = sqlite3_finalize(stmt);
        stmt = nullptr;

        if (finalizeResult != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db));
        }

        executeSQL("COMMIT;");
        transactionStarted = false;

    } catch (...) {
        if (stmt) {
            sqlite3_finalize(stmt);
        }

        if (transactionStarted) {
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        }

        sqlite3_close(db);
        throw;
    }

    sqlite3_close(db);
}