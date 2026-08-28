#pragma once

#include <cstdint>

namespace tc8::net {

// The outcome of a CAPABILITY operation on the socket seam — the operations a
// network stack may structurally not have (multicast membership, ARP/neighbor
// cache control), as opposed to the plain socket plumbing whose natural answer
// is an fd, a byte count or a bool.
//
// Those operations fail for structurally different reasons and a caller needs
// them apart: a wrong interface name is an operator mistake to correct, while a
// stack that cannot perform the primitive at all is a permanent property of the
// target. Collapsed into one `false` the two are indistinguishable, and a test
// system driving the seam cannot tell "you asked wrongly" from "do not ask
// here" — it would have to read the backend source for the target it happens to
// be pointed at.
//
// The vocabulary is deliberately protocol-NEUTRAL: this layer stays free of
// testability wire codes, which is why the RID-returning primitives live on
// tc8::testability::SocketBackend instead. A testability consumer projects a
// status onto a PRS_TPSP §6.8 Result ID with ridFromOpStatus()
// (tc8/testability_protocol.h) — one place where that spec reading lives; the
// Upper Tester server, which has no RIDs, reads the statuses directly.
enum class OpStatus : std::uint8_t {
    // Performed. Also the answer when the requested end state already held and
    // there was nothing to do: these operations are idempotent by contract, so
    // "already absent" / "nothing to flush" is success, not an error.
    Ok,

    // No interface by that name — or, where the interface is selected by an
    // address, none carrying it. The request is well-formed; what it names does
    // not exist on this stack.
    UnknownInterface,

    // The request itself is unusable: a nonsensical value, or a combination the
    // seam cannot honor (an address not reachable via the named interface).
    // Distinct from UnknownInterface — both parts may exist yet not go together.
    InvalidArgument,

    // The stack can do this; THIS PROCESS may not. The operation is privileged
    // and the privilege is absent, so the same call from a privileged process
    // would succeed. A property of the caller, never of the target.
    NotPermitted,

    // This build's stack cannot perform the operation AT ALL, at any privilege:
    // a compile-time-absent feature, or a knob the stack does not expose. A
    // permanent property of the target — a caller should stop asking rather
    // than retry or escalate.
    Unsupported,

    // Attempted and refused for a reason none of the above name (a full table,
    // a transport error). The residual bucket, so the named ones stay precise.
    Failed,
};

// The status's name, for a diagnostic a human reads — a module log line, a test
// failure message. Static storage, never null. This exists because the reason an
// operation failed was previously recoverable only by reading the backend source
// for whichever target the caller happened to be pointed at; a name in the log
// is the cheapest way that stops being true.
constexpr const char *toString(OpStatus status) {
    switch (status) {
        case OpStatus::Ok:
            return "Ok";
        case OpStatus::UnknownInterface:
            return "UnknownInterface";
        case OpStatus::InvalidArgument:
            return "InvalidArgument";
        case OpStatus::NotPermitted:
            return "NotPermitted";
        case OpStatus::Unsupported:
            return "Unsupported";
        case OpStatus::Failed:
            return "Failed";
    }
    // Unreachable for a valid enumerator; the switch is exhaustive and -Wswitch
    // is an error here, so a new status cannot be added without landing above.
    return "?";
}

}  // namespace tc8::net
