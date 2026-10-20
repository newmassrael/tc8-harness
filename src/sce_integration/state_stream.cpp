#include "sce_integration/state_stream.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <set>
#include <string>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sce_integration/captured_trace.h"  // appendJsonEscaped

namespace tc8::sce {

namespace {

// `,"spec_step":N` for a step the case declared, nothing for one it did not.
void appendSpecStep(std::string &line, int spec_step) {
    if (spec_step == ::tc8::stimulus::kNoSpecStep) {
        return;
    }
    char num[32];
    std::snprintf(num, sizeof(num), ",\"spec_step\":%d", spec_step);
    line.append(num);
}

// A JSON string, or `null` for a value the machine has no single id for.
void appendNullableString(std::string &line, const std::optional<std::string> &value) {
    if (!value.has_value()) {
        line.append("null");
        return;
    }
    line.push_back('"');
    appendJsonEscaped(line, *value);
    line.push_back('"');
}

}  // namespace

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
    if (ev.src_port != 0) {
        std::snprintf(num, sizeof(num), ",\"src_port\":%u", static_cast<unsigned>(ev.src_port));
        line.append(num);
    }
    std::snprintf(num, sizeof(num), ",\"bytes\":%zu", ev.bytes);
    line.append(num);
    appendSpecStep(line, ev.spec_step);
    emit(std::move(line));
}

void StateStream::frame(const ::tc8::FrameSummary &f) {
    // Bounded like the tx lines, for the same reason: a busy wire must not turn a
    // progress file into a per-packet log, nor put a write on the observer's thread
    // for every frame of a burst.
    const unsigned seq = frame_lines_.fetch_add(1, std::memory_order_relaxed);
    if (seq > kMaxFrameLines) {
        return;
    }
    if (seq == kMaxFrameLines) {
        emit("{\"event\":\"frame_suppressed\",\"after\":" + std::to_string(kMaxFrameLines));
        return;
    }
    char num[64];
    std::string line = "{\"event\":\"frame\"";
    if (f.has_ips) {
        // Network byte order: the first octet is the lowest byte in memory.
        const auto *s = reinterpret_cast<const unsigned char *>(&f.src_ip_be);
        const auto *d = reinterpret_cast<const unsigned char *>(&f.dst_ip_be);
        std::snprintf(num, sizeof(num), ",\"src_ip\":\"%u.%u.%u.%u\",\"dst_ip\":\"%u.%u.%u.%u\"",
                      s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]);
        line.append(num);
    }
    switch (f.proto) {
        case ::tc8::FrameSummary::Proto::kUdp: line.append(",\"proto\":\"udp\""); break;
        case ::tc8::FrameSummary::Proto::kTcp: line.append(",\"proto\":\"tcp\""); break;
        case ::tc8::FrameSummary::Proto::kOther: line.append(",\"proto\":\"other\""); break;
    }
    if (f.has_ports) {
        std::snprintf(num, sizeof(num), ",\"src_port\":%u,\"dst_port\":%u",
                      static_cast<unsigned>(f.src_port), static_cast<unsigned>(f.dst_port));
        line.append(num);
    }
    std::snprintf(num, sizeof(num), ",\"len\":%u", static_cast<unsigned>(f.wire_len));
    line.append(num);
    emitAt(std::move(line), f.t_us);
}

void StateStream::observerUnavailable(std::string_view reason) {
    if (observer_unavailable_written_.exchange(true, std::memory_order_relaxed)) {
        return;
    }
    std::string line = "{\"event\":\"observer_unavailable\",\"reason\":\"";
    appendJsonEscaped(line, reason);
    line.push_back('"');
    emit(std::move(line));
}

void StateStream::spec(const SpecProcedure &procedure) {
    char num[32];
    std::string line = "{\"event\":\"spec\",\"steps\":[";
    bool first = true;
    for (const SpecStep &s : procedure.steps) {
        if (!first) line.push_back(',');
        first = false;
        std::snprintf(num, sizeof(num), "{\"n\":%d,", s.n);
        line.append(num);
        line.append("\"actor\":\"");
        appendJsonEscaped(line, s.actor);
        line.append("\",\"text\":\"");
        appendJsonEscaped(line, s.text);
        line.append("\"}");
    }
    line.append("],\"checks\":[");
    first = true;
    for (const SpecCheck &c : procedure.checks) {
        if (!first) line.push_back(',');
        first = false;
        std::snprintf(num, sizeof(num), "{\"step\":%d,", c.step);
        line.append(num);
        line.append("\"mark\":\"");
        appendJsonEscaped(line, c.mark);
        line.append("\",\"text\":\"");
        appendJsonEscaped(line, c.text);
        line.append("\"}");
    }
    line.push_back(']');
    emit(std::move(line));
}

void StateStream::specInvalid(const std::vector<std::string> &problems) {
    std::string line = "{\"event\":\"spec_invalid\",\"problems\":[";
    bool first = true;
    for (const auto &p : problems) {
        if (!first) line.push_back(',');
        first = false;
        line.push_back('"');
        appendJsonEscaped(line, p);
        line.push_back('"');
    }
    line.push_back(']');
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

void StateStream::machine(const MachineDescription &d) {
    std::string line = "{\"event\":\"machine\",\"states\":[";
    bool first = true;
    for (const auto &s : d.states) {
        if (!first) line.push_back(',');
        first = false;
        line.append("{\"id\":\"");
        appendJsonEscaped(line, s.id);
        line.append("\",\"initial\":");
        line.append(s.initial ? "true" : "false");
        line.append(",\"final\":");
        line.append(s.final ? "true" : "false");
        line.push_back('}');
    }
    line.append("],\"events\":[");
    first = true;
    for (const auto &e : d.events) {
        if (!first) line.push_back(',');
        first = false;
        line.push_back('"');
        appendJsonEscaped(line, e);
        line.push_back('"');
    }
    line.append("],\"transitions\":");
    if (!d.transitions.has_value()) {
        // Not known: a machine whose design did not declare a table. Never an empty list.
        line.append("null");
    } else {
        line.push_back('[');
        first = true;
        for (const auto &t : *d.transitions) {
            if (!first) line.push_back(',');
            first = false;
            line.append("{\"from\":\"");
            appendJsonEscaped(line, t.from);
            line.append("\",\"to\":");
            appendNullableString(line, t.to);
            line.append(",\"event\":");
            appendNullableString(line, t.event);
            line.append(",\"index\":");
            line.append(std::to_string(t.index));
            line.push_back('}');
        }
        line.push_back(']');
        if (d.source_hash.has_value()) {
            line.append(",\"source_hash\":\"");
            appendJsonEscaped(line, *d.source_hash);
            line.push_back('"');
        }
    }
    emit(std::move(line));
}

void StateStream::transitionsInvalid(const std::vector<std::string> &problems) {
    std::string line = "{\"event\":\"transitions_invalid\",\"problems\":[";
    bool first = true;
    for (const auto &p : problems) {
        if (!first) line.push_back(',');
        first = false;
        line.push_back('"');
        appendJsonEscaped(line, p);
        line.push_back('"');
    }
    line.push_back(']');
    emit(std::move(line));
}

std::vector<std::string> validateTransitions(const MachineDescription &d) {
    std::vector<std::string> problems;
    if (!d.transitions.has_value()) return problems;

    std::set<std::string> states;
    for (const auto &s : d.states) states.insert(s.id);
    const std::set<std::string> events(d.events.begin(), d.events.end());
    std::set<std::pair<std::string, int>> seen;

    for (const auto &t : *d.transitions) {
        const std::string label = "a transition of '" + t.from + "' (index " + std::to_string(t.index) + ")";
        if (states.count(t.from) == 0) {
            problems.push_back(label + " departs from a state the machine does not have");
        }
        if (t.to.has_value() && states.count(*t.to) == 0) {
            problems.push_back(label + " arrives at '" + *t.to + "', which the machine does not have");
        }
        if (t.event.has_value() && events.count(*t.event) == 0) {
            problems.push_back(label + " is triggered by '" + *t.event + "', an event the machine does not name");
        }
        if (!seen.insert({t.from, t.index}).second) {
            problems.push_back(label + " repeats the index of another transition of that state");
        }
    }
    return problems;
}

void StateStream::transition(int step, std::string_view trigger, std::string_view from,
                             std::string_view to, int pcap_frame_idx,
                             const std::vector<int> &spec_steps) {
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
    if (!spec_steps.empty()) {
        appendSpecStep(line, spec_steps.front());
    }
    if (spec_steps.size() > 1) {
        line.append(",\"spec_steps\":[");
        for (std::size_t i = 0; i < spec_steps.size(); ++i) {
            std::snprintf(num, sizeof(num), i == 0 ? "%d" : ",%d", spec_steps[i]);
            line.append(num);
        }
        line.push_back(']');
    }
    emit(std::move(line));
}

void StateStream::end(std::string_view final_state) {
    std::string line = "{\"event\":\"end\",\"final_state\":\"";
    appendJsonEscaped(line, final_state);
    line.push_back('"');
    emit(std::move(line), /*final=*/true);
}

void StateStream::emit(std::string line, bool final) {
    const auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    emitAt(std::move(line), now_us, final);
}

void StateStream::emitAt(std::string line, std::int64_t t_us, bool final) {
    // Under one lock so that `end` is the last line however the others are timed: a
    // thread the case detached, or the observer's, may still be mid-line when the run
    // ends, and its line must lose that race, not follow `end`. The lock is held for
    // one write into the page cache.
    std::lock_guard<std::mutex> lock(write_mu_);
    if (ended_ || failed_.load(std::memory_order_relaxed)) {
        return;
    }
    char tail[48];
    std::snprintf(tail, sizeof(tail), ",\"t_us\":%lld}\n", static_cast<long long>(t_us));
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
    if (final) {
        ended_ = true;
    }
}

}  // namespace tc8::sce
