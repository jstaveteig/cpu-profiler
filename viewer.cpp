#include "recording.hpp"
#include "reconstruct.hpp"

#include <QAction>
#include <QApplication>
#include <QFileDialog>
#include <QFileInfo>
#include <QMenu>
#include <QProcess>
#include <QFile>
#include <QHash>
#include <QCursor>
#include <QStandardPaths>
#include <QKeySequence>
#include <QFontDatabase>
#include <QMainWindow>
#include <QMessageBox>
#include <QMouseEvent>
#include <QResizeEvent>
#include <QPainter>
#include <QScrollBar>
#include <QStringList>
#include <QStyleFactory>
#include <QToolBar>
#include <QWheelEvent>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <map>
#include <utility>
#include <vector>
#include <sys/stat.h>
#include <elf.h>

namespace {
constexpr int labelWidth = 184;
constexpr int rowHeight = 32;
constexpr int rowsTop = 112;
constexpr int footerHeight = 77;

struct Evidence {
    bool selected = false;
    Interval interval{};
    int blockingStack = -1;
    int blockingProcess = -1;
    bool hasWaking = false;
    int wakerTid = -1;
    std::uint64_t wakingNs = 0;
    int wakingStack = -1;
    int wakingProcess = -1;
};

struct ThreadRow {
    std::int32_t tid{};
    std::uint64_t lifetime{};
    std::vector<Interval> intervals;
};

QColor stateColor(threadState state) {
    switch (state) {
        case threadState::Running:  return QColor("#7EABBC");
        case threadState::Runnable: return QColor("#D8B56B");
        case threadState::Sleeping: return QColor("#BCC4CB");
        case threadState::Other:    return QColor("#B79ABB");
        case threadState::Unknown:  return QColor("#E7E7E7");
    }
    return QColor("#E7E7E7");
}

QString stateName(threadState state) {
    switch (state) {
        case threadState::Running:  return "Running";
        case threadState::Runnable: return "Runnable";
        case threadState::Sleeping: return "Sleeping";
        case threadState::Other:    return "Other";
        case threadState::Unknown:  return "Unknown";
    }
    return "Unknown";
}

QString formatTime(double ns) {
    const double a = std::abs(ns);
    if (a >= 1e9) return QString::number(ns / 1e9, 'f', 3) + " s";
    if (a >= 1e6) return QString::number(ns / 1e6, 'f', 3) + " ms";
    if (a >= 1e3) return QString::number(ns / 1e3, 'f', 2) + " us";
    return QString::number(ns, 'f', 0) + " ns";
}

// Symbol lookup is deliberately conservative. Only use mappings captured for
// the exact process, before the stack observation, and only if the file has
// not changed since capture. No mapping => no speculative function name.
class SymbolResolver {
public:
    void reset(const std::vector<ExecutableMapping>& maps) {
        maps_ = maps;
        cache_.clear();
    }

    QString resolve(std::uint64_t pc, int pid, std::uint64_t timestamp) {
        if (pid <= 0 || pc == 0 || QStandardPaths::findExecutable("addr2line").isEmpty())
            return {};
        const ExecutableMapping* best = nullptr;
        for (const auto& m : maps_) {
            if (m.process_pid != pid || m.observed_ns > timestamp ||
                pc < m.start || pc >= m.end) continue;
            if (!best || m.observed_ns > best->observed_ns) best = &m;
        }
        if (!best) return {};
        const auto& m = *best;
        struct stat st{};
        if (::stat(m.path.c_str(), &st) != 0 ||
            static_cast<std::uint64_t>(st.st_ino) != m.inode ||
            static_cast<std::uint64_t>(st.st_dev) != m.device ||
            std::int64_t(st.st_mtim.tv_sec) * 1'000'000'000 + st.st_mtim.tv_nsec != m.modified_ns)
            return {};
        const QString filename = QString::fromStdString(m.path);
        QFile file(filename);
        if (!file.open(QIODevice::ReadOnly)) return {};
        const QByteArray elf = file.read(20);
        if (elf.size() < 20 || elf[0] != '\x7f' || elf.mid(1, 3) != "ELF" ||
            static_cast<unsigned char>(elf[5]) != ELFDATA2LSB) return {};
        const auto type = static_cast<unsigned char>(elf[16]) |
                          (static_cast<unsigned char>(elf[17]) << 8);
        if (type != ET_DYN && type != ET_EXEC) return {};
        const auto address = type == ET_DYN ? pc - m.start + m.file_offset : pc;
        const QString key = filename + ':' + QString::number(static_cast<qulonglong>(address), 16);
        if (cache_.contains(key)) return cache_.value(key);
        QProcess process;
        process.start("addr2line", {"-C", "-f", "-e", filename,
                                    "0x" + QString::number(static_cast<qulonglong>(address), 16)});
        QString result;
        if (process.waitForFinished(300) && process.exitStatus() == QProcess::NormalExit &&
            process.exitCode() == 0) {
            const auto lines = QString::fromLocal8Bit(process.readAllStandardOutput())
                                   .trimmed().split('\n');
            if (lines.size() >= 2 && lines[0].trimmed() != "??") {
                result = lines[0].trimmed();
                if (!lines[1].startsWith("??"))
                    result += "  —  " + lines[1].trimmed();
            }
        }
        cache_.insert(key, result);
        return result;
    }

private:
    std::vector<ExecutableMapping> maps_;
    QHash<QString, QString> cache_;
};

class TimelineWidget final : public QWidget {
public:
    explicit TimelineWidget(QWidget* parent = nullptr)
        : QWidget(parent), scrollbar_(new QScrollBar(Qt::Vertical, this)) {
        setMinimumSize(660, 360);
        setMouseTracking(true);
        setFocusPolicy(Qt::StrongFocus);
        scrollbar_->setSingleStep(1);
        connect(scrollbar_, &QScrollBar::valueChanged, this, [this] { update(); });
        updateScrollbar();
    }

    std::function<void()> onSelectionChanged;

    void setTrace(const std::vector<traceEvent>& events,
                  std::vector<Interval> intervals,
                  const QString& filename,
                  const RecordingQuality& quality) {
        quality_ = quality;
        switches_.clear();
        waking_.clear();
        wakeups_.clear();
        for (const auto& event : events) {
            if (const auto* sw = std::get_if<schedEvent>(&event)) {
                switches_.push_back(*sw);
            } else if (const auto* wake = std::get_if<wakeEvent>(&event)) {
                if (wake->header.type == EVENT_WAKING)
                    waking_.push_back(*wake);
                else if (wake->header.type == EVENT_WAKEUP ||
                         wake->header.type == EVENT_WAKEUP_NEW)
                    wakeups_.push_back(*wake);
            }
        }

        std::map<std::pair<std::int32_t, std::uint64_t>, ThreadRow> grouped;
        for (auto& interval : intervals) {
            if (interval.end_ns <= interval.start_ns) continue;
            const auto key = std::make_pair(interval.tid, interval.lifetime_id);
            auto& row = grouped[key];
            row.tid = interval.tid;
            row.lifetime = interval.lifetime_id;
            row.intervals.push_back(std::move(interval));
        }

        rows_.clear();
        rows_.reserve(grouped.size());
        for (auto& [key, row] : grouped) {
            std::sort(row.intervals.begin(), row.intervals.end(),
                      [](const Interval& a, const Interval& b) {
                          if (a.start_ns != b.start_ns) return a.start_ns < b.start_ns;
                          return a.end_ns < b.end_ns;
                      });
            rows_.push_back(std::move(row));
        }

        minNs_ = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t maxNs = 0;
        for (const auto& event : events) {
            const auto timestamp = std::visit(
                [](const auto& item) { return item.header.timestamp_ns; }, event);
            minNs_ = std::min(minNs_, timestamp);
            maxNs = std::max(maxNs, timestamp);
        }
        if (events.empty()) minNs_ = 0;
        for (const auto& row : rows_) {
            for (const auto& interval : row.intervals) {
                minNs_ = std::min(minNs_, interval.start_ns);
                maxNs = std::max(maxNs, interval.end_ns);
            }
        }
        fullSpan_ = std::max(1.0, static_cast<double>(maxNs - minNs_));
        filename_ = QFileInfo(filename).fileName();
        eventCount_ = events.size();
        selectedRow_ = selectedInterval_ = -1;
        selectedSource_.clear();
        hoverRow_ = hoverInterval_ = -1;
        fit();
        if (onSelectionChanged) onSelectionChanged();
    }

    Evidence selectedEvidence() const {
        Evidence e;
        if (selectedRow_ < 0 || selectedRow_ >= static_cast<int>(rows_.size()) ||
            selectedInterval_ < 0 ||
            selectedInterval_ >= static_cast<int>(rows_[selectedRow_].intervals.size())) return e;
        e.selected = true;
        e.interval = rows_[selectedRow_].intervals[selectedInterval_];
        const auto& in = e.interval;
        // A block-site user stack is captured at the switch-out that opens the wait.
        if (in.state == threadState::Sleeping || in.state == threadState::Other) {
            for (const auto& sw : switches_) {
                if (sw.prev_tid == in.tid && sw.header.timestamp_ns == in.start_ns) {
                    e.blockingStack = sw.stack_id;
                    e.blockingProcess = sw.process_pid;
                    break;
                }
            }
        }
        if (in.state != threadState::Sleeping) return e;
        bool foundWakeup = false;
        for (const auto& wake : wakeups_) {
            if (wake.target_tid == in.tid && wake.header.timestamp_ns == in.end_ns) {
                foundWakeup = true;
                break;
            }
        }
        if (!foundWakeup) return e;
        // Closest earlier waking observation for this target; this is evidence,
        // not proof of a lock owner or the complete reason for the wait.
        for (const auto& wake : waking_) {
            if (wake.target_tid != in.tid || wake.header.timestamp_ns < in.start_ns ||
                wake.header.timestamp_ns > in.end_ns) continue;
            if (!e.hasWaking || wake.header.timestamp_ns > e.wakingNs) {
                e.hasWaking = true;
                e.wakerTid = wake.current_tid;
                e.wakingNs = wake.header.timestamp_ns;
                e.wakingStack = wake.stack_id;
                e.wakingProcess = wake.process_pid;
            }
        }
        return e;
    }

    bool canJumpToWaker(const Evidence& e) const {
        // TID 0 identifies kernel/idle execution context, not a userspace thread.
        if (!e.hasWaking || e.wakerTid <= 0) return false;
        for (const auto& row : rows_) {
            if (row.tid != e.wakerTid) continue;
            for (const auto& interval : row.intervals) {
                if (interval.start_ns <= e.wakingNs && e.wakingNs < interval.end_ns)
                    return true;
            }
        }
        return false;
    }

    bool jumpToWaker() {
        const Evidence e = selectedEvidence();
        if (!canJumpToWaker(e)) return false;
        for (int r = 0; r < static_cast<int>(rows_.size()); ++r) {
            if (rows_[r].tid != e.wakerTid) continue;
            const auto& intervals = rows_[r].intervals;
            for (int i = 0; i < static_cast<int>(intervals.size()); ++i) {
                if (intervals[i].start_ns <= e.wakingNs && e.wakingNs < intervals[i].end_ns) {
                    selectedRow_ = r;
                    selectedInterval_ = i;
                    selectedSource_.clear();
                    scrollbar_->setValue(std::min(r, scrollbar_->maximum()));
                    const double center = relativeNs(e.wakingNs);
                    viewStart_ = std::clamp(center - viewSpan_ * 0.5, 0.0,
                                            std::max(0.0, fullSpan_ - viewSpan_));
                    update();
                    if (onSelectionChanged) onSelectionChanged();
                    return true;
                }
            }
        }
        return false; // waker was external or had no reconstructable interval
    }

    struct RankedInterval { int row; int index; std::uint64_t duration; };
    std::vector<RankedInterval> longest(threadState state, int limit = 8) const {
        std::vector<RankedInterval> result;
        for (int r = 0; r < static_cast<int>(rows_.size()); ++r)
            for (int i = 0; i < static_cast<int>(rows_[r].intervals.size()); ++i) {
                const auto& in = rows_[r].intervals[i];
                if (in.state == state && in.end_ns > in.start_ns)
                    result.push_back({r, i, in.end_ns - in.start_ns});
            }
        std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
            return a.duration > b.duration;
        });
        if (result.size() > static_cast<std::size_t>(limit)) result.resize(limit);
        return result;
    }

    QString rankedLabel(const RankedInterval& rank) const {
        const auto& in = rows_[rank.row].intervals[rank.index];
        return QString("%1   ·   TID %2").arg(formatTime(double(rank.duration))).arg(in.tid);
    }

    void selectInterval(int row, int index) {
        if (row < 0 || row >= static_cast<int>(rows_.size()) || index < 0 ||
            index >= static_cast<int>(rows_[row].intervals.size())) return;
        selectedRow_ = row;
        selectedInterval_ = index;
        const auto& in = rows_[row].intervals[index];
        scrollbar_->setValue(std::min(row, scrollbar_->maximum()));
        const double center = relativeNs(in.start_ns) + double(in.end_ns - in.start_ns) / 2.0;
        const double minSpan = std::min(fullSpan_, 1'000.0);
        viewSpan_ = std::clamp(double(in.end_ns - in.start_ns) * 3.0, minSpan, fullSpan_);
        viewStart_ = std::clamp(center - viewSpan_ / 2, 0.0,
                                std::max(0.0, fullSpan_ - viewSpan_));
        update();
        if (onSelectionChanged) onSelectionChanged();
    }

    void setSourceSummary(const QString& source) {
        selectedSource_ = source;
        update();
    }

    void fit() {
        viewStart_ = 0;
        viewSpan_ = fullSpan_;
        scrollbar_->setValue(0);
        updateScrollbar();
        update();
    }

protected:
    void resizeEvent(QResizeEvent* event) override {
        QWidget::resizeEvent(event);
        updateScrollbar();
    }

    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.fillRect(rect(), Qt::white);
        QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        font.setPointSize(9);
        p.setFont(font);

        // Small utilitarian header.
        p.fillRect(QRect(0, 0, width(), 49), QColor("#F5F5F5"));
        p.setPen(QColor("#D7D7D7"));
        p.drawLine(0, 48, width(), 48);
        p.setFont(font);
        p.setPen(QColor("#040404"));
        QString info = filename_.isEmpty() ? "No recording loaded" : filename_;
        if (!filename_.isEmpty() && quality_.available) {
            if (!quality_.complete) info += "  |  INCOMPLETE";
            if (quality_.dropped_events)
                info += QString("  |  %1 dropped")
                    .arg(static_cast<qulonglong>(quality_.dropped_events));
            if (quality_.tracking_failures)
                info += QString("  |  %1 tracking failures")
                    .arg(static_cast<qulonglong>(quality_.tracking_failures));
        }
        p.drawText(QRect(labelWidth, 10, std::max(0, plotRight() - labelWidth), 29),
                   Qt::AlignRight | Qt::AlignVCenter, info);

        if (filename_.isEmpty()) {
            p.setPen(QColor("#7A7A7A"));
            p.drawText(rect().adjusted(0, 0, 0, -footerHeight), Qt::AlignCenter,
                       "open a .scope recording (ctrl+o)");
            drawFooter(p);
            return;
        }

        const int bottom = height() - footerHeight;
        p.setPen(QColor("#777777"));
        p.drawText(16, 90, "thread / lifetime");

        const int offset = scrollbar_->value();
        const int visible = std::max(0, (bottom - rowsTop + rowHeight - 1) / rowHeight);
        for (int i = offset; i < std::min<int>(rows_.size(), offset + visible); ++i) {
            const int y = rowsTop + (i - offset) * rowHeight;
            if (i % 2 == 1) p.fillRect(0, y, plotRight(), rowHeight, QColor("#FAFAFA"));
            p.setPen(QColor("#ECECEC"));
            p.drawLine(0, y + rowHeight - 1, plotRight(), y + rowHeight - 1);
        }

        const double graphWidth = std::max(1, plotRight() - labelWidth);
        const double tickGoal = viewSpan_ * 115.0 / graphWidth;
        const double magnitude = std::pow(10.0, std::floor(std::log10(std::max(1.0, tickGoal))));
        double tick = magnitude;
        if (tickGoal > tick) tick = 2 * magnitude;
        if (tickGoal > tick) tick = 5 * magnitude;
        if (tickGoal > tick) tick = 10 * magnitude;
        const double firstTick = std::ceil(viewStart_ / tick) * tick;
        for (double t = firstTick; t <= viewStart_ + viewSpan_; t += tick) {
            const double x = timeToX(t);
            if (x < labelWidth || x > plotRight()) continue;
            p.setPen(QColor("#777777"));
            p.drawText(QRectF(x - 45, 68, 90, 25), Qt::AlignCenter, formatTime(t));
            p.setPen(QColor("#E8E8E8"));
            p.drawLine(QPointF(x, rowsTop), QPointF(x, bottom));
        }
        p.setPen(QColor("#C6C6C6"));
        p.drawLine(labelWidth - 8, 101, labelWidth - 8, bottom);

        p.save();
        p.setClipRect(QRect(labelWidth, rowsTop,
                            std::max(0, plotRight() - labelWidth),
                            std::max(0, bottom - rowsTop)));
        for (int i = offset; i < std::min<int>(rows_.size(), offset + visible); ++i) {
            const ThreadRow& row = rows_[i];
            const int y = rowsTop + (i - offset) * rowHeight;
            const double earliest = viewStart_;
            const double latest = viewStart_ + viewSpan_;
            auto it = std::lower_bound(row.intervals.begin(), row.intervals.end(), earliest,
                [this](const Interval& interval, double t) {
                    return relativeNs(interval.start_ns) < t;
                });
            if (it != row.intervals.begin()) --it;
            for (; it != row.intervals.end(); ++it) {
                const double start = relativeNs(it->start_ns);
                const double end = relativeNs(it->end_ns);
                if (start > latest) break;
                if (end < earliest) continue;
                const int j = static_cast<int>(it - row.intervals.begin());
                const QRectF bar = intervalRect(i, *it);
                p.fillRect(bar, stateColor(it->state));
                if (i == selectedRow_ && j == selectedInterval_) {
                    p.setPen(QPen(QColor("#295A8C"), 2));
                    p.drawRect(bar.adjusted(0, 0, -1, -1));
                } else if (i == hoverRow_ && j == hoverInterval_) {
                    p.setPen(QPen(QColor("#747474"), 1));
                    p.drawRect(bar.adjusted(0, 0, -1, -1));
                }
            }
        }
        p.restore();

        for (int i = offset; i < std::min<int>(rows_.size(), offset + visible); ++i) {
            const int y = rowsTop + (i - offset) * rowHeight;
            const auto& row = rows_[i];
            p.setPen(QColor("#383838"));
            const QString label = QString("tid %1  /  #%2").arg(row.tid).arg(static_cast<qulonglong>(row.lifetime));
            p.drawText(QRect(14, y, labelWidth - 27, rowHeight),
                       Qt::AlignVCenter | Qt::AlignLeft, label);
        }
        if (rows_.empty()) {
            p.setPen(QColor("#777777"));
            p.drawText(QRect(labelWidth, rowsTop, plotRight() - labelWidth, bottom - rowsTop),
                       Qt::AlignCenter, "no complete scheduling intervals");
        }
        drawFooter(p);
    }

    void wheelEvent(QWheelEvent* event) override {
        if (filename_.isEmpty()) return;
        const double turns = event->angleDelta().y() / 120.0;
        if (event->modifiers() & Qt::ControlModifier) {
            const double frac = std::clamp(
                (event->position().x() - labelWidth) / std::max(1.0, double(plotRight() - labelWidth)),
                0.0, 1.0);
            const double anchor = viewStart_ + frac * viewSpan_;
            const double minSpan = std::min(fullSpan_, 1'000.0); // 1 us at most zoom
            const double nextSpan = std::clamp(viewSpan_ / std::pow(1.25, turns), minSpan, fullSpan_);
            viewSpan_ = nextSpan;
            viewStart_ = std::clamp(anchor - frac * viewSpan_, 0.0,
                                    std::max(0.0, fullSpan_ - viewSpan_));
            update();
        } else if (event->modifiers() & Qt::ShiftModifier) {
            pan(-turns * viewSpan_ * 0.15);
        } else {
            scrollbar_->setValue(scrollbar_->value() - static_cast<int>(std::round(turns * 3)));
        }
        event->accept();
    }

    void mousePressEvent(QMouseEvent* event) override {
        if (event->button() != Qt::LeftButton || event->position().x() < labelWidth) return;
        mouseDown_ = event->position();
        startAtMouseDown_ = viewStart_;
        dragging_ = true;
        moved_ = false;
        setCursor(Qt::ClosedHandCursor);
    }

    void mouseMoveEvent(QMouseEvent* event) override {
        if (dragging_) {
            const double pixels = event->position().x() - mouseDown_.x();
            if (std::abs(pixels) > 3.0) moved_ = true;
            if (moved_) {
                viewStart_ = std::clamp(
                    startAtMouseDown_ - pixels * viewSpan_ /
                        std::max(1.0, double(plotRight() - labelWidth)),
                    0.0, std::max(0.0, fullSpan_ - viewSpan_));
                update();
            }
        } else {
            const auto [r, i] = hitTest(event->position());
            if (r != hoverRow_ || i != hoverInterval_) {
                hoverRow_ = r;
                hoverInterval_ = i;
                update();
            }
        }
    }

    void mouseReleaseEvent(QMouseEvent* event) override {
        if (event->button() != Qt::LeftButton || !dragging_) return;
        dragging_ = false;
        setCursor(Qt::ArrowCursor);
        if (!moved_) {
            const auto [r, i] = hitTest(event->position());
            selectedRow_ = r;
            selectedInterval_ = i;
            selectedSource_.clear();
            if (onSelectionChanged) onSelectionChanged();
        }
        update();
    }

private:
    std::vector<ThreadRow> rows_;
    std::vector<schedEvent> switches_;
    std::vector<wakeEvent> waking_;
    std::vector<wakeEvent> wakeups_;
    RecordingQuality quality_{};
    QScrollBar* scrollbar_;
    QString filename_;
    QString selectedSource_;
    std::size_t eventCount_ = 0;
    std::uint64_t minNs_ = 0;
    double fullSpan_ = 1;
    double viewStart_ = 0;
    double viewSpan_ = 1;
    int selectedRow_ = -1, selectedInterval_ = -1;
    int hoverRow_ = -1, hoverInterval_ = -1;
    bool dragging_ = false, moved_ = false;
    QPointF mouseDown_;
    double startAtMouseDown_ = 0;

    int plotRight() const { return width() - (scrollbar_->isVisible() ? 22 : 14); }

    double relativeNs(std::uint64_t absolute) const {
        if (absolute >= minNs_) return static_cast<double>(absolute - minNs_);
        return -static_cast<double>(minNs_ - absolute);
    }

    double timeToX(double relative) const {
        return labelWidth + (relative - viewStart_) *
            std::max(1, plotRight() - labelWidth) / viewSpan_;
    }

    QRectF intervalRect(int row, const Interval& interval) const {
        const double x = timeToX(relativeNs(interval.start_ns));
        const double endX = timeToX(relativeNs(interval.end_ns));
        const double y = rowsTop + (row - scrollbar_->value()) * rowHeight + 7;
        return QRectF(x, y, std::max(1.0, endX - x), 18);
    }

    void pan(double offset) {
        viewStart_ = std::clamp(viewStart_ + offset, 0.0,
                                std::max(0.0, fullSpan_ - viewSpan_));
        update();
    }

    void updateScrollbar() {
        const int bottom = height() - footerHeight;
        const int visibleRows = std::max(1, (bottom - rowsTop) / rowHeight);
        scrollbar_->setRange(0, std::max(0, static_cast<int>(rows_.size()) - visibleRows));
        scrollbar_->setPageStep(visibleRows);
        const bool needed = static_cast<int>(rows_.size()) > visibleRows;
        scrollbar_->setVisible(needed);
        scrollbar_->setGeometry(width() - 17, rowsTop, 17, std::max(0, bottom - rowsTop));
    }

    std::pair<int, int> hitTest(const QPointF& position) const {
        const int bottom = height() - footerHeight;
        if (position.x() < labelWidth || position.x() > plotRight() ||
            position.y() < rowsTop || position.y() >= bottom) return {-1, -1};
        const int row = scrollbar_->value() +
                        static_cast<int>((position.y() - rowsTop) / rowHeight);
        if (row < 0 || row >= static_cast<int>(rows_.size())) return {-1, -1};
        const auto& intervals = rows_[row].intervals;
        for (int i = 0; i < static_cast<int>(intervals.size()); ++i) {
            if (intervalRect(row, intervals[i]).contains(position)) return {row, i};
        }
        return {-1, -1};
    }

    void drawFooter(QPainter& p) const {
        const int y = height() - footerHeight;
        p.fillRect(QRect(0, y, width(), footerHeight), QColor("#F5F5F5"));
        p.setPen(QColor("#D4D4D4"));
        p.drawLine(0, y, width(), y);
        const int r = selectedRow_ >= 0 ? selectedRow_ : hoverRow_;
        const int i = selectedRow_ >= 0 ? selectedInterval_ : hoverInterval_;
        p.setPen(QColor("#333333"));
        if (r < 0 || i < 0 || r >= static_cast<int>(rows_.size()) ||
            i >= static_cast<int>(rows_[r].intervals.size())) {
            p.drawText(16, y + 45,
                       "Click on an interval to inspect");
            return;
        }
        const auto& row = rows_[r];
        const auto& in = row.intervals[i];
        const double start = relativeNs(in.start_ns);
        const double end = relativeNs(in.end_ns);
        p.drawText(16, y + (selectedSource_.isEmpty() ? 43 : 29),
            QString("TID %1  ·  %2  ·  %3%4")
                .arg(row.tid)
                .arg(stateName(in.state))
                .arg(formatTime(end - start))
                .arg(in.cpu >= 0 ? QString("  ·  CPU %1").arg(in.cpu) : QString()));
        if (!selectedSource_.isEmpty()) {
            p.setPen(QColor("#565656"));
            p.drawText(QRect(16, y + 37, width() - 32, 29),
                       Qt::AlignVCenter, p.fontMetrics().elidedText(
                           selectedSource_, Qt::ElideRight, width() - 36));
        }
    }
};
} // namespace

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setStyle(QStyleFactory::create("Fusion"));

    QMainWindow window;
    window.setWindowTitle("Scope");
    window.resize(1100, 670);
    auto* timeline = new TimelineWidget(&window);
    window.setCentralWidget(timeline);

    SymbolResolver resolver;
    QString loadedPath;
    std::vector<std::uint64_t> selectedBlockingFrames;
    std::vector<std::uint64_t> selectedWakingFrames;
    Evidence selectedEvidence;

    auto* toolbar = window.addToolBar("controls");
    toolbar->setMovable(false);
    toolbar->setFloatable(false);
    toolbar->setToolButtonStyle(Qt::ToolButtonTextOnly);
    toolbar->setStyleSheet("QToolBar { background: #F7F7F7; border-bottom: 1px solid #D7D7D7; spacing: 8px; padding: 4px; }"
                           "QToolButton { border: 1px solid #BDBDBD; background: white; padding: 4px 12px; }"
                           "QToolButton:hover { background: #EAEAEA; }");

    auto* stackAction = new QAction("Stack", &window);
    auto* followAction = new QAction("Follow wakeup", &window);
    stackAction->setVisible(false);
    followAction->setVisible(false);

    auto updateEvidence = [&] {
        selectedEvidence = timeline->selectedEvidence();
        selectedBlockingFrames.clear();
        selectedWakingFrames.clear();
        QString site;
        const auto& e = selectedEvidence;
        if (e.selected && !loadedPath.isEmpty()) {
            auto load = [&](int id) {
                if (id < 0) return std::vector<std::uint64_t>{};
                try { return loadStack(loadedPath.toStdString(), id); }
                catch (const std::exception&) { return std::vector<std::uint64_t>{}; }
            };
            selectedBlockingFrames = load(e.blockingStack);
            if (e.hasWaking) selectedWakingFrames = load(e.wakingStack);
            if (!selectedBlockingFrames.empty()) {
                // Try several frames: the first may be a runtime or trampoline.
                for (std::size_t n = 0; n < std::min<std::size_t>(6, selectedBlockingFrames.size()); ++n) {
                    const QString candidate = resolver.resolve(
                        selectedBlockingFrames[n], e.blockingProcess, e.interval.start_ns);
                    if (!candidate.isEmpty()) {
                        if (site.isEmpty()) site = candidate;
                        if (candidate.contains(".cpp:") || candidate.contains(".cc:") ||
                            candidate.contains(".c:") || candidate.contains(".hpp:")) {
                            site = candidate;
                            break;
                        }
                    }
                }
            }
        }
        timeline->setSourceSummary(site.isEmpty() ? QString() : "Blocked at " + site);
        stackAction->setVisible(!selectedBlockingFrames.empty() || !selectedWakingFrames.empty());
        followAction->setVisible(timeline->canJumpToWaker(e));
    };
    timeline->onSelectionChanged = updateEvidence;
    QObject::connect(followAction, &QAction::triggered, timeline, [&] {
        timeline->jumpToWaker();
    });
    QObject::connect(stackAction, &QAction::triggered, &window, [&] {
        QMenu menu(&window);
        auto frames = [&](const QString& title, const std::vector<std::uint64_t>& pcs,
                          int pid, std::uint64_t timestamp) {
            if (pcs.empty()) return;
            auto* heading = menu.addAction(title);
            heading->setEnabled(false);
            for (std::size_t i = 0; i < std::min<std::size_t>(pcs.size(), 16); ++i) {
                const auto resolved = resolver.resolve(pcs[i], pid, timestamp);
                const auto text = resolved.isEmpty()
                    ? QString("0x%1").arg(static_cast<qulonglong>(pcs[i]), 0, 16)
                    : resolved;
                auto* action = menu.addAction("    " + text);
                action->setEnabled(false);
            }
        };
        frames("Blocking-site frames", selectedBlockingFrames,
               selectedEvidence.blockingProcess, selectedEvidence.interval.start_ns);
        frames("Waking-context frames", selectedWakingFrames,
               selectedEvidence.wakingProcess, selectedEvidence.wakingNs);
        menu.exec(QCursor::pos());
    });

    auto loadFile = [&](const QString& path) {
        if (path.isEmpty()) return;
        try {
            auto events = loadRecording(path.toStdString());
            auto quality = loadRecordingQuality(path.toStdString());
            auto intervals = reconstruct(events);
            resolver.reset(loadMappings(path.toStdString()));
            loadedPath = path;
            timeline->setTrace(events, std::move(intervals), path, quality);
            window.setWindowTitle(QString("Scope — %1").arg(QFileInfo(path).fileName()));
        } catch (const std::exception& e) {
            QMessageBox::critical(&window, "unable to open recording", QString::fromUtf8(e.what()));
        }
    };

    auto* openAction = toolbar->addAction("Open…");
    openAction->setShortcut(QKeySequence("Ctrl+O"));
    QObject::connect(openAction, &QAction::triggered, &window, [&] {
        const QString path = QFileDialog::getOpenFileName(
            &window, "open scope recording", {}, "scope recordings (*.scope);;All files (*)");
        loadFile(path);
    });

    auto* fitAction = toolbar->addAction("Fit");
    fitAction->setShortcut(QKeySequence("F"));
    QObject::connect(fitAction, &QAction::triggered, timeline, [timeline] { timeline->fit(); });

    auto* stallsAction = toolbar->addAction("Stalls");
    QObject::connect(stallsAction, &QAction::triggered, &window, [&] {
        QMenu menu(&window);
        const auto addGroup = [&](const QString& label, threadState state) {
            auto* title = menu.addAction(label);
            title->setEnabled(false);
            const auto ranks = timeline->longest(state);
            if (ranks.empty()) {
                auto* none = menu.addAction("    None in recording");
                none->setEnabled(false);
            }
            for (const auto& rank : ranks) {
                auto* action = menu.addAction("    " + timeline->rankedLabel(rank));
                QObject::connect(action, &QAction::triggered, &menu, [timeline, rank] {
                    timeline->selectInterval(rank.row, rank.index);
                });
            }
        };
        addGroup("CPU scheduling delays", threadState::Runnable);
        menu.addSeparator();
        addGroup("Sleeping intervals (may be idle)", threadState::Sleeping);
        menu.exec(QCursor::pos());
    });

    toolbar->addAction(stackAction);
    toolbar->addAction(followAction);

    window.show();
    if (argc > 1) loadFile(QString::fromLocal8Bit(argv[1]));
    return app.exec();
}
