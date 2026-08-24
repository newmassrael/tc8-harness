#pragma once
// The launcher-to-harness end of the start-order barrier: reading the `--go-file`.
//
// WHY THIS EXISTS
// ---------------
// `--ready-file` is the harness telling its launcher "the capture is armed, you may
// start the DUT". That is one-directional: the harness then walks on to
// `kickStimulus` without ever learning that the DUT did start. A case whose stimulus
// is fire-and-forget — a datagram with no retry and no solicited response to
// re-drive it — loses that race whenever the DUT is the slower of the two, and
// nothing reports it: the datagram IS on the wire, the case simply observes
// nothing. Measured on a two-machine wire, three On-Event CAN triggers were all
// answered by the DUT host's kernel with ICMP port-unreachable, the last of them
// missing the DUT's bind of its receive port by 147 ms.
//
// `--go-file` is the answering half. The launcher creates it once it has decided
// whether the DUT is bound, and this reads that decision.
//
// WHY THE FILE'S CONTENT CARRIES THE ANSWER
// -----------------------------------------
// Presence alone cannot say it. The file appears when the launcher has DECIDED,
// which is not the same as the DUT being up, so:
//
//     absent     -> not decided yet; keep waiting.
//     empty      -> the launcher OBSERVED the DUT announce every endpoint bound.
//     non-empty  -> it did not, and the content is a one-line reason to echo.
//
// Two values rather than presence-versus-absence because the FAST failure is the
// one that matters: a DUT that died at startup is decided by the launcher in
// milliseconds, and encoding that as "the file never appears" would make every such
// case sit out the reader's whole ceiling — hours across a several-hundred case
// sweep, for a fact already known.
//
// The launcher must publish it atomically (write elsewhere, rename into place), so
// a file that exists always has its complete content. Without that, a reader could
// see a half-written reason as an empty file and conclude the DUT was bound — which
// is the one direction this must never fail in.
//
// WHY IT IS A HEADER OF ITS OWN
// ------------------------------
// So the contract above has one tested home instead of living inside a CLI command
// where only the WRITER's side (the orchestrator's Rust unit tests) was pinned. A
// reader that quietly started treating mere existence as "bound" would leave those
// tests green while removing the guard.

#include <cstdio>
#include <string>

namespace tc8 {

/// What the launcher's `--go-file` says about the DUT.
enum class DutReadyState {
    /// No signal yet — the launcher has not finished deciding.
    Undecided,
    /// The launcher observed the DUT announce that every receive endpoint is bound.
    Bound,
    /// It could not establish that. `reason` says why.
    NotBound,
};

struct DutReadyReport {
    DutReadyState state = DutReadyState::Undecided;
    /// Set only for `NotBound`; the launcher's one-line reason, newline-trimmed.
    std::string reason;
};

/// Read the signal at `path` once, without blocking. Callers poll this.
///
/// A read error is reported as `Undecided` rather than as a state about the DUT: not
/// being able to read the launcher's answer says nothing about whether the DUT came
/// up, and reporting it as `Bound` would be a silent false clearance.
inline DutReadyReport readDutReadySignal(const std::string &path) {
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        return DutReadyReport{};
    }
    // A reason is one line; a cap keeps a runaway writer from being read unbounded.
    // Truncation cannot flip the verdict — any non-empty prefix still reads NotBound.
    char buf[512];
    const std::size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    std::string body(buf, n);
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r')) {
        body.pop_back();
    }
    if (body.empty()) {
        return DutReadyReport{DutReadyState::Bound, {}};
    }
    return DutReadyReport{DutReadyState::NotBound, std::move(body)};
}

}  // namespace tc8
