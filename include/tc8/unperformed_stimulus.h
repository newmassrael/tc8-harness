#pragma once
// Run-scoped record of a stimulus the tester could not perform.
//
// WHY THIS EXISTS
// ---------------
// A case grades the DUT's response to something the tester does. When the tester
// cannot do that thing — an iptables filter that would not install, a route it
// could not add — the case still runs, still observes, and still concludes. The
// conclusion is then about a DUT that was never actually subjected to the
// stimulus, and it is not merely unproven: it can be confidently WRONG in the
// expensive direction. Measured on a host without iptables, a connection-lost
// case reported `fail:event_..._sent_after_tcp_connection_lost` while the capture
// showed the tester ACKing the DUT's stream to the last frame. The connection was
// never cut; the DUT was behaving correctly and was failed for it.
//
// This is the stimulus-axis twin of the capture-axis rule in
// `tc8::captureProvenComplete` / `CaptureStats::multicast_groups`. That one asks
// "could we have OBSERVED it?"; this one asks "did the thing we are grading a
// response to actually HAPPEN?". Both are preconditions of a verdict, and the
// reason the capture side is not enough is that they fail independently: a
// perfect capture of a stimulus that never fired still yields a confident,
// fictitious verdict.
//
// WHY IT IS A LEDGER RATHER THAN A RETURN VALUE
// ---------------------------------------------
// The scopes that install these filters are RAII objects constructed deep inside
// case code and services, with no channel back to the one place that emits the
// verdict. Threading a status through every such call site would put the
// invariant in the hands of every case author — the same argument the capture
// rule makes for living at the verdict site rather than in ~107 per-case
// conditions. An invariant that must be remembered is one that gets forgotten,
// and a forgotten one here is a false FAIL against somebody's hardware.
//
// Deliberately NOT fatal: a failed install must not abort a multi-case sweep. It
// is recorded so the verdict can read it, which is the whole of the ask.

#include <mutex>
#include <string>

namespace tc8 {

/// The stimuli whose absence invalidates a verdict. Names are stable identifiers
/// that appear in the inconclusive reason, so an operator reading a report can
/// tell WHICH stimulus did not happen.
class UnperformedStimulus {
public:
    /// Record that `name` could not be performed. Idempotent in effect: the FIRST
    /// record wins, so a run that fails several stimuli reports a deterministic
    /// reason rather than one that depends on destruction order.
    static void record(const std::string &name) {
        std::lock_guard<std::mutex> lk(mutex());
        if (first().empty()) first() = name;
    }

    /// Whether any stimulus went unperformed this run.
    static bool any() {
        std::lock_guard<std::mutex> lk(mutex());
        return !first().empty();
    }

    /// The inconclusive reason naming the first unperformed stimulus, or an empty
    /// string when none was recorded.
    static std::string reason() {
        std::lock_guard<std::mutex> lk(mutex());
        if (first().empty()) return {};
        return "stimulus_" + first() + "_not_performed";
    }

    /// Clear the ledger. One case runs per harness invocation, so this exists for
    /// tests and for any future in-process multi-case driver — a stale record
    /// leaking into the next case would turn this guard into its own false
    /// inconclusive.
    static void reset() {
        std::lock_guard<std::mutex> lk(mutex());
        first().clear();
    }

private:
    // Function-local statics: header-only, one instance across every TU that
    // includes this, and no static-init-order dependency (the scopes that write
    // here are constructed from case code, but a future static-storage caller
    // would still be safe).
    static std::string &first() {
        static std::string v;
        return v;
    }
    static std::mutex &mutex() {
        static std::mutex m;
        return m;
    }
};

}  // namespace tc8
