#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>

#include "stimulus/tx_observer.h"

// Live state-transition stream (`test --state-stream <path>`).
//
// A case's transitions are recorded as they fire (TestRunner::recordTransition)
// but written out once, when the case ends (`<pcap>.trace.json`). A process
// outside the harness therefore cannot tell that a case has started, or which
// state its machine is in. This is the other half: the same events, appended to a
// file as they happen, one JSON object per line.
//
//   {"event":"start","case":"<suite:ID>","initial":"<state>","t_us":N}
//   {"event":"transition","step":N,"trigger":"<event>","from":"<state>",
//    "to":"<state>","pcap_frame_idx":N|null,"t_us":N}
//   {"event":"end","final_state":"<state>","t_us":N}
//
// and, once the stream is bound as the process's tx observer (stimulus/tx_observer.h),
// one line per frame or datagram the TESTER successfully sent:
//
//   {"event":"tx","emitter":"<emit* name>","transport":"udp_unicast","iface":"<if>",
//    "dst":"a.b.c.d:port","bytes":N,"t_us":N}
//
// `emitter` is absent when the send was reached by a route no emit*/send* entry point
// names; `iface` is absent when the primitive takes none; `dst` is absent when the
// sender does not know it (a raw Ethernet frame is opaque to it). A tx line says THAT
// the tester sent and where, never WHAT: the saved pcap holds the frame, and a reader
// decodes it there. It is reported after the send, so it may follow the frame's own
// pcap record by a moment and must not be used to order the two.
// A stimulus runs before the machine starts, so tx lines can precede the `start` line;
// they are the only lines a watcher sees while a stimulus is in progress.
//
// State and trigger names are the SCXML ids `trace.json` carries (same source,
// same strings). `pcap_frame_idx` is null where `trace.json` has null: a step with
// no retained frame behind it (a timer firing). `t_us` is microseconds since the Unix
// epoch (system_clock), the pcap timestamp domain, sampled when the line is
// written.
//
// What a reader may rely on, and what it may not:
//   - One record per line, each written with a single write(2) call, so a tailing
//     reader never sees a record split across two reads of a live file.
//   - The stream is PROGRESS, never the verdict. The verdict is what the harness
//     prints and exits with, and `trace.json` records; nothing here feeds either.
//     A missing, empty or truncated stream (the process died, the disk filled)
//     changes no verdict, and the file may simply stop without an `end` line.
//   - A transition line reports the NET change of one macrostep, exactly as the
//     trace does: a step that passes through an intermediate state to a later one
//     is one line, from the first to the last. A reader drawing the machine must
//     not assume `from` is adjacent to `to` in the static graph.
//   - The file is created when the case is set up, before the stimulus runs, so its
//     existence says the case has begun; the `start` line follows once the state
//     machine is initialised (after the stimulus, because deadlines arm there).
//
// Off the capture path: the sink is a regular file (anything else is refused at
// open), so a write is a page-cache copy of ~150 bytes, never a wait on a reader.
// A failed write is dropped silently and permanently disables the stream, so a
// short write cannot leave a half record that the next line would be glued onto.
//
// Callable from more than one thread (a responder sends from its own): each record is
// one write(2) on an O_APPEND file, which the kernel orders whole, and the disable flag
// is atomic.
namespace tc8::sce {

class StateStream final : public ::tc8::stimulus::ITxObserver {
public:
    // Creates (truncating) `path` and returns the stream, or nullptr when the path
    // cannot be opened or is not a regular file. `case_label` is the case identity
    // the `start` line carries (`suite:ID`, bare for the in-tree suite).
    static std::unique_ptr<StateStream> open(const std::string &path,
                                             std::string_view case_label);

    ~StateStream() override;
    StateStream(const StateStream &) = delete;
    StateStream &operator=(const StateStream &) = delete;

    void start(std::string_view initial_state);
    void transition(int step, std::string_view trigger, std::string_view from,
                    std::string_view to, int pcap_frame_idx);
    void end(std::string_view final_state);

    // ITxObserver: the `tx` line.
    void onTx(const ::tc8::stimulus::TxEvent &ev) override;

private:
    StateStream(int fd, std::string_view case_label);

    // Appends the `,"t_us":N}` tail and newline, then writes the whole line.
    void emit(std::string line);

    const int         fd_;
    std::atomic<bool> failed_{false};
    std::string       case_label_;
};

}  // namespace tc8::sce
