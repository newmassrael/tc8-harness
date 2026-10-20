#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "sce_integration/spec_steps.h"
#include "stimulus/tx_observer.h"
#include "tc8/frame_summary.h"

// Live state-transition stream (`test --state-stream <path>`).
//
// A case's transitions are recorded as they fire (TestRunner::recordTransition)
// but written out once, when the case ends (`<pcap>.trace.json`). A process
// outside the harness therefore cannot tell that a case has started, or which
// state its machine is in. This is the other half: the same events, appended to a
// file as they happen, one JSON object per line.
//
//   {"event":"case_begin","case":"<suite:ID>","t_us":N}      first line, at case setup
//   {"event":"stimulus_begin","t_us":N}                      around kickStimulus,
//   {"event":"stimulus_end","t_us":N}                        always a pair
//   {"event":"start","case":"<suite:ID>","initial":"<state>","t_us":N}
//   {"event":"machine","states":[{"id":"<state>","initial":bool,"final":bool},...],
//    "events":["<event>",...],"transitions":[...]|null,"t_us":N}           once, after start
//   {"event":"transition","step":N,"trigger":"<event>","from":"<state>",
//    "to":"<state>","pcap_frame_idx":N|null,"t_us":N}
//   {"event":"end","final_state":"<state>","t_us":N}
//
// and, once the stream is bound as the process's tx observer (stimulus/tx_observer.h),
// one line per frame or datagram the TESTER successfully sent:
//
//   {"event":"tx","emitter":"<emit* name>"|null,"transport":"udp_unicast","iface":"<if>",
//    "dst":"a.b.c.d:port","src_port":N,"bytes":N,"t_us":N}
//
// `emitter` is null when the send was reached by a route no emit*/send* entry point
// names (kept, so a missing name is visible); `iface` is absent when the primitive takes none; `dst` is absent when the
// sender does not know it (a raw Ethernet frame is opaque to it); `src_port`, the
// tester's own port, is present only on a TCP connection, where with `dst` it names the
// connection. A TCP control segment the kernel sent for a connect() or an accept()
// ("tcp_connect", "tcp_connect_ack", "tcp_accept") is identified by that connection and
// its flags, not by its time (TxEvent::transport). A tx line says THAT
// the tester sent and where, never WHAT: the saved pcap holds the frame, and a reader
// decodes it there. It is reported after the send, so it may follow the frame's own
// pcap record by a moment and must not be used to order the two.
// A stimulus runs before the machine starts, so tx lines come between `stimulus_begin`
// and `stimulus_end`, before the `start` line; they are, with the frame lines below,
// the only lines a watcher sees while a stimulus is in progress. At most 1000 tx lines
// are written per run, then one {"event":"tx_suppressed","after":1000}: a looping route
// must not make a progress file a per-packet log.
//
// The DUT's side comes from a passive observer (capture/passive_tap.h): a separate
// read-only capture handle on the interface, so a frame is reported as the kernel
// delivers it, not when the capture the verdict rests on is next drained:
//
//   {"event":"frame","src_ip":"a.b.c.d","dst_ip":"a.b.c.d","proto":"udp"|"tcp"|"other",
//    "src_port":N,"dst_port":N,"len":N,"t_us":N}
//
// Here `t_us` is the frame's KERNEL CAPTURE time (the pcap record header's clock and
// precision), not the time the line was written, so a frame line can sit after lines
// with a later `t_us`; order frames by it. `len` is the length on the wire. The ips are
// absent for a frame that is neither IPv4 nor IPv4 ARP (for ARP they are the sender and
// target protocol addresses, proto "other"); the ports are absent where the transport
// header is not in the captured bytes. Nothing of the payload is decoded: a reader takes
// a frame's meaning from the saved pcap. Frames are those the case's own capture filter
// admits, on the primary interface. At most 5000 are written per run, then one
// {"event":"frame_suppressed","after":5000}. If the observer cannot be set up (no
// privilege, interface gone) the run goes on without it and at most one
// {"event":"observer_unavailable","reason":"<text>"} is written, never a verdict change.
// The observer ends before the `end` line, which stays the last of the run.
//
// The `machine` line is the compiled machine's own declaration, read from the generated
// code's name tables (not the SCXML file): every state id with whether it is the initial
// one and whether it is final, and every event id it names (the vocabulary a `trigger`
// is drawn from; `error.execution` is the platform's). Order is the machine's
// enumeration order, not the document's.
//
// Its `transitions` member is the machine's own table when the design declares one
// (`<scxml sce:transition-table="emit">`, which makes the generator write the table into
// the policy), and null when it does not:
//
//   "transitions":[{"from":"<state>","to":"<state>"|null,"event":"<event>"|null,"index":N},...]
//
// With a list the line also carries `"source_hash":"<hex>"`, the digest of the SCXML
// source set the table was generated from. The harness cannot check it (it holds no
// SCXML at run time, and the table and the machine come out of one generation), but a
// reader that has the SCXML can: `sce-codegen transition-table --header <file>` prints
// the same `source_hash` in its first line, and a differing one means the stream was
// made by another revision of that design. Absent where the list is.
//
// A list means "these are all of them", in the machine's document order; `index` is the
// transition's position within its `from` state. `to` is null for a transition with no
// target, or whose first target is a history; `event` is null for an eventless one, a
// wildcard, a prefix such as `error.*`, or several descriptors. Null never means "none":
// it is "not known", and a reader that gets it draws the states alone. A table that
// disagrees with the machine's own name tables is not written (the member is null) and
// `{"event":"transitions_invalid","problems":["<sentence>",...],"t_us":N}` follows the
// machine line instead: a wrong table is worse than none.
//
// A case that declares its specification's own steps (sce_integration/spec_steps.h) adds:
//
//   {"event":"spec","steps":[{"n":1,"actor":"<who>","text":"<step>"},...],
//    "checks":[{"step":N,"mark":"<mark>","text":"<item>"},...],"t_us":N}   after case_begin
//   {"event":"spec_invalid","problems":["<sentence>",...],"t_us":N}   after machine, only
//                                          if the case's table names what the machine lacks
//
// and a "spec_step":N member on the `tx` lines the case tagged and on the `transition`
// lines its table maps; both are ABSENT, not null, where the case said nothing. The text
// is the case's own, escaped and passed through untouched; the harness neither reads
// nor shortens it. A step is a separate axis from the machine's states: nothing about a
// state, a trigger or a verdict changes with it. `frame` lines are never tagged: a
// reader joins a frame to the tx or transition that explains it by time. A case without
// a table produces none of this, byte for byte.
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
//   - The file is created, and `case_begin` written, when the case is set up, before
//     the stimulus runs; the `start` line follows once the state machine is
//     initialised (after the stimulus, because deadlines arm there).
//
// Off the capture path: the sink is a regular file (anything else is refused at
// open), so a write is a page-cache copy of ~150 bytes, never a wait on a reader.
// A failed write is dropped silently and permanently disables the stream, so a
// short write cannot leave a half record that the next line would be glued onto.
//
// Callable from more than one thread (a responder sends from its own, the frame
// observer reads on its own): each record is one write(2) on an O_APPEND file, taken
// under a lock that also makes `end` the last line of the run: a line another thread
// offers after it is dropped. The disable flag is atomic.
namespace tc8::sce {

// What the compiled state machine declares: the vocabulary of the `machine` line.
struct MachineDescription {
    struct State {
        std::string id;
        bool        initial = false;
        bool        final   = false;
    };
    // One entry of the machine's own transition table (the generated policy's
    // `transitions`). `to` and `event` are absent where the transition has no single id
    // in the name tables (see the stream's header comment).
    struct Transition {
        std::string                from;
        std::optional<std::string> to;
        std::optional<std::string> event;
        int                        index = 0;
    };
    std::vector<State>       states;
    std::vector<std::string> events;
    // nullopt = the machine carries no table, so nothing is known; a list, even an
    // empty one, is the complete set.
    std::optional<std::vector<Transition>> transitions;
    // The digest of the SCXML source set the table was generated from (the policy's
    // `sourceHash()`); set with `transitions` and never without it.
    std::optional<std::string> source_hash;
};

// What is wrong with a machine's transition table against the machine's own states and
// events, one sentence each; empty when it is sound or there is no table. Checks that every
// `from` and `to` is a declared state, every `event` a declared event, and that no two
// entries of one state share an `index`.
std::vector<std::string> validateTransitions(const MachineDescription &description);

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

    // Bracket the case's stimulus (kickStimulus). Always a pair, also for a case with
    // none; `start` follows `stimulus_end`.
    void stimulusBegin();
    void stimulusEnd();

    // The `spec` line, once, right after case_begin, for a case that declares one.
    void spec(const SpecProcedure &procedure);
    // The `spec_invalid` line: what is wrong with the case's table against its machine.
    // Not called with an empty list.
    void specInvalid(const std::vector<std::string> &problems);

    void start(std::string_view initial_state);
    // The `machine` line, once, right after `start`.
    void machine(const MachineDescription &description);
    // The `transitions_invalid` line: what is wrong with the machine's table against its
    // own name tables. Not called with an empty list.
    void transitionsInvalid(const std::vector<std::string> &problems);
    // `spec_step` is the case's step for this transition, or kNoSpecStep.
    void transition(int step, std::string_view trigger, std::string_view from,
                    std::string_view to, int pcap_frame_idx,
                    int spec_step = ::tc8::stimulus::kNoSpecStep);
    void end(std::string_view final_state);

    // ITxObserver: the `tx` line.
    void onTx(const ::tc8::stimulus::TxEvent &ev) override;

    // The `frame` line, stamped with the frame's own capture time. Called from the
    // passive observer's thread.
    void frame(const ::tc8::FrameSummary &f);

    // The observer could not be set up. At most one line is written, however often
    // this is called.
    void observerUnavailable(std::string_view reason);

private:
    StateStream(int fd, std::string_view case_label);

    // Appends the `,"t_us":N}` tail and newline, then writes the whole line. The
    // first form stamps the time of writing, the second a time the caller supplies.
    // `final` marks the `end` line: nothing is written after it.
    void emit(std::string line, bool final = false);
    void emitAt(std::string line, std::int64_t t_us, bool final = false);

    // Upper bound on tx lines in one run (see onTx).
    static constexpr unsigned kMaxTxLines = 1000;
    // Upper bound on frame lines in one run (see frame).
    static constexpr unsigned kMaxFrameLines = 5000;

    const int           fd_;
    std::mutex          write_mu_;  // orders a write against `end`; guards ended_
    bool                ended_ = false;
    std::atomic<bool>   failed_{false};
    std::atomic<unsigned> tx_lines_{0};
    std::atomic<unsigned> frame_lines_{0};
    std::atomic<bool>   observer_unavailable_written_{false};
    std::string       case_label_;
};

}  // namespace tc8::sce
