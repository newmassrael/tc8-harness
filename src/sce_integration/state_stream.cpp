#include "sce_integration/state_stream.h"

#include <cerrno>
#include <chrono>
#include <cstdio>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sce_integration/captured_trace.h"  // appendJsonEscaped

namespace tc8::sce {

std::unique_ptr<StateStream> StateStream::open(const std::string &path,
                                               std::string_view case_label) {
    // O_NONBLOCK so that opening a FIFO with no reader fails instead of hanging
    // the harness before it has captured anything; the file type check below then
    // refuses it. O_APPEND so every record lands at the end however the file was
    // reached.
    const int fd = ::open(path.c_str(),
                          O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_NONBLOCK | O_CLOEXEC, 0644);
    if (fd < 0) {
        return nullptr;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return nullptr;
    }
    std::unique_ptr<StateStream> stream(new StateStream(fd, case_label));
    // The file's first line, so "started, in the stimulus" is distinguishable from
    // "not started" before the machine exists.
    std::string line = "{\"event\":\"case_begin\",\"case\":\"";
    appendJsonEscaped(line, case_label);
    line.push_back('"');
    stream->emit(std::move(line));
    return stream;
}

void StateStream::stimulusBegin() {
    emit("{\"event\":\"stimulus_begin\"");
}

void StateStream::stimulusEnd() {
    emit("{\"event\":\"stimulus_end\"");
}

StateStream::StateStream(int fd, std::string_view case_label)
    : fd_(fd), case_label_(case_label) {}

StateStream::~StateStream() {
    ::close(fd_);
}

void StateStream::onTx(const ::tc8::stimulus::TxEvent &ev) {
    // A bounded number of tx lines per run. A route that loops (a burst of datagrams)
    // would otherwise turn a progress file into a per-packet log and put a write on the
    // stimulus's own cadence for every one. The line that says so is the last tx line.
    const unsigned seq = tx_lines_.fetch_add(1, std::memory_order_relaxed);
    if (seq > kMaxTxLines) {
        return;
    }
    if (seq == kMaxTxLines) {
        emit("{\"event\":\"tx_suppressed\",\"after\":" + std::to_string(kMaxTxLines));
        return;
    }
    std::string line = "{\"event\":\"tx\",\"emitter\":";
    if (!ev.emitter.empty()) {
        line.push_back('"');
        appendJsonEscaped(line, ev.emitter);
        line.push_back('"');
    } else {
        // Not dropped: a send no entry point named is visible as a missing name.
        line.append("null");
    }
    line.append(",\"transport\":\"");
    appendJsonEscaped(line, ev.transport);
    line.push_back('"');
    if (!ev.iface.empty()) {
        line.append(",\"iface\":\"");
        appendJsonEscaped(line, ev.iface);
        line.push_back('"');
    }
    char num[48];
    if (ev.dst_ip_be != 0) {
        // Network byte order: the first octet is the lowest byte in memory.
        const auto *o = reinterpret_cast<const unsigned char *>(&ev.dst_ip_be);
        std::snprintf(num, sizeof(num), "%u.%u.%u.%u:%u", o[0], o[1], o[2], o[3],
                      static_cast<unsigned>(ev.dst_port));
        line.append(",\"dst\":\"");
        line.append(num);
        line.push_back('"');
    }
    std::snprintf(num, sizeof(num), ",\"bytes\":%zu", ev.bytes);
    line.append(num);
    emit(std::move(line));
}

void StateStream::start(std::string_view initial_state) {
    std::string line = "{\"event\":\"start\",\"case\":\"";
    appendJsonEscaped(line, case_label_);
    line.append("\",\"initial\":\"");
    appendJsonEscaped(line, initial_state);
    line.push_back('"');
    emit(std::move(line));
}

void StateStream::transition(int step, std::string_view trigger, std::string_view from,
                             std::string_view to, int pcap_frame_idx) {
    char num[32];
    std::string line = "{\"event\":\"transition\",\"step\":";
    std::snprintf(num, sizeof(num), "%d", step);
    line.append(num);
    line.append(",\"trigger\":\"");
    appendJsonEscaped(line, trigger);
    line.append("\",\"from\":\"");
    appendJsonEscaped(line, from);
    line.append("\",\"to\":\"");
    appendJsonEscaped(line, to);
    line.append("\",\"pcap_frame_idx\":");
    if (pcap_frame_idx >= 0) {
        std::snprintf(num, sizeof(num), "%d", pcap_frame_idx);
        line.append(num);
    } else {
        line.append("null");
    }
    emit(std::move(line));
}

void StateStream::end(std::string_view final_state) {
    std::string line = "{\"event\":\"end\",\"final_state\":\"";
    appendJsonEscaped(line, final_state);
    line.push_back('"');
    emit(std::move(line));
}

void StateStream::emit(std::string line) {
    if (failed_.load(std::memory_order_relaxed)) {
        return;
    }
    const auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    char tail[48];
    std::snprintf(tail, sizeof(tail), ",\"t_us\":%lld}\n", static_cast<long long>(now_us));
    line.append(tail);

    ssize_t n;
    do {
        n = ::write(fd_, line.data(), line.size());
    } while (n < 0 && errno == EINTR);

    // The stream never decides anything, so a failure is dropped, not reported.
    // But it is also final: after a short write the file ends mid-record, and the
    // next line would be appended to that fragment, turning two records into one
    // unparseable line. Stopping leaves a file that merely ends early. The fd stays
    // open until the destructor: another thread may be inside its own write.
    if (n != static_cast<ssize_t>(line.size())) {
        failed_.store(true, std::memory_order_relaxed);
    }
}

}  // namespace tc8::sce
