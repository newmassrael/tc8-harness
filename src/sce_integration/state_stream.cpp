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
    return std::unique_ptr<StateStream>(new StateStream(fd, case_label));
}

StateStream::StateStream(int fd, std::string_view case_label)
    : fd_(fd), case_label_(case_label) {}

StateStream::~StateStream() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
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
    if (fd_ < 0) {
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
    // unparseable line. Stopping leaves a file that merely ends early.
    if (n != static_cast<ssize_t>(line.size())) {
        ::close(fd_);
        fd_ = -1;
    }
}

}  // namespace tc8::sce
