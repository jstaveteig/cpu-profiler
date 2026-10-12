#define main scopeViewerMain
#include "../viewer.cpp"
#undef main

#include <iostream>
#include <stdexcept>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct TimelineTest {
    static void run(TimelineWidget& view) {
        constexpr std::uint64_t ms = 1'000'000;
        auto marker = [&](int id, int phase, int time, const char* name) {
            spanEvent e{};
            e.header.type = EVENT_SPAN;
            e.header.timestamp_ns = time * ms;
            e.namespace_tid = 7;
            e.span_id = id;
            e.phase = phase;
            std::strncpy(e.name, name, sizeof(e.name) - 1);
            return e;
        };
        schedEvent sw{};
        sw.header.type = EVENT_SWITCH;
        sw.header.timestamp_ns = ms;
        sw.prev_tid = 700;
        sw.namespace_tid = 7;
        std::strcpy(sw.prev_comm, "worker-00");
        std::vector<traceEvent> events{
            sw, marker(1, 1, 1, "worker"), marker(2, 1, 1, "work"),
            marker(2, 2, 4, "work"), marker(3, 1, 4, "sleep"),
            marker(3, 2, 9, "sleep"), marker(1, 2, 10, "worker")};
        std::vector<Interval> intervals{{700, ms, 10 * ms, threadState::Running, 0, 1}};
        view.setTrace(events, intervals, "nested.scope", {});
        require(view.rows_.size() == 1, "Namespace TID mapping");
        require(view.rows_[0].spans.size() == 3, "Paired spans");
        const auto& spans = view.rows_[0].spans;
        require(spans[0].name == "worker" && spans[0].depth == 0, "Parent first on equal start");
        require(spans[1].depth == 1 && spans[2].depth == 1, "Nested and adjacent lanes");
        const auto parent = view.spanRect(0, spans[0]);
        const auto child = view.spanRect(0, spans[1]);
        require(!parent.intersects(child), "Nested span overlap");
        require(!child.intersects(view.intervalRect(0, intervals[0])), "Scheduler overlap");
        require(view.spanHitTest(child.center()) == std::pair{0, 1}, "Child hit test");
        require(view.spanHitTest(parent.center()) == std::pair{0, 0}, "Parent hit test");
        QMouseEvent click(QEvent::MouseButtonDblClick, child.center(), child.center(),
                          Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
        const auto full = view.viewSpan_;
        QApplication::sendEvent(&view, &click);
        require(view.selectedSpanIndex_ == 1 && view.viewSpan_ < full, "Span zoom");
        view.setTrace({sw}, intervals, "scheduler.scope", {});
        require(!view.spansVisible_ && view.spanDepth_ == 0 && view.laneHeight() == 32,
                "Scheduler-only recording");
        view.setTrace({}, {}, "empty.scope", {});
        require(view.rows_.empty(), "Empty recording");
    }

    static void preview(TimelineWidget& view, const QString& recording, const QString& output) {
        const auto events = loadRecording(recording.toStdString());
        view.setTrace(events, reconstruct(events), recording,
                      loadRecordingQuality(recording.toStdString()));
        int markedThreads = 0;
        for (int i = 0; i < int(view.rows_.size()); ++i) {
            if (view.rows_[i].spans.empty()) continue;
            require(view.rows_[i].tid > 0, "Unmapped span row");
            require(view.rows_[i].spans.size() == 401, "Missing stress spans");
            ++markedThreads;
        }
        require(markedThreads == 32, "Expected 32 instrumented workers");
        const auto worker = std::find_if(view.rows_.begin(), view.rows_.end(),
            [](const ThreadRow& row) { return !row.spans.empty(); });
        view.viewStart_ = view.relativeNs(worker->spans.front().start_ns);
        view.viewSpan_ = 40'000'000;
        view.scrollbar_->setValue(int(worker - view.rows_.begin()));
        view.show();
        QApplication::processEvents();
        require(view.grab().save(output), "Preview image");
    }
};
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    try {
        TimelineWidget view;
        view.resize(1440, 900);
        TimelineTest::run(view);
        if (argc == 3) TimelineTest::preview(view, argv[1], argv[2]);
        std::cout << "PASS: span layout, selection, zoom, and recording reload\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
