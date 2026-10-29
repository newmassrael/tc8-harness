#pragma once

#include "tc8/protocol_frames/ipv4_envelope.h"

namespace tc8 {

// Shared "carrying IPv4 header" surface for the SCE Named Contexts that observe an L4
// datagram: UDP, TCP and DHCPv4. It is the frame-side `Ipv4Envelope` itself, so the type
// of each field and its zero default are defined once for the frame and for the context,
// and `copyIpv4Envelope` is one assignment that cannot miss a field.
//
// Owns `ip_tos`, `ip_identification`, `ip_flags` and `ip_fragment_offset`. IPv4_FRAGMENTS_05
// asserts a DUT-emitted datagram carries MF=0 / offset=0; a retransmission case reads the
// Identification; a socket-option case reads the TOS the DUT put on a datagram.
//
// Deliberately NOT inherited by Ipv4Captured. That context represents a whole observed
// IPv4 header as a cohesive unit and names these fields natively (`flags`,
// `fragment_offset`, `tos`, `identification`) beside its other header fields. Folding it
// into this mixin would fragment that header, and force its `captured.flags` SCXML conds to
// rename, entangled with TcpCaptured, which also exposes a `flags` member. The native name
// (`flags`) and the borrowed one (`ip_flags`) are intentionally different.
//
// Inherited (not composed as a nested member) so SCXML conditions keep the single-dot
// `cpp:captured.ip_flags == ...` form that SCE's expression rewriter requires — it rewrites
// `captured.X` into `this->captured_->X` but not `captured.X.Y` (see
// docs/scxml_guard_expressions.md).
//
// Data only, and it shares no ancestor with the other Captured mixins, so a context
// carries independent data-only subobjects with no diamond.
using CapturedIpv4Envelope = Ipv4Envelope;

// Copy the envelope from the frame to the context: the one place the four fields are
// moved, for every L4 type.
inline void copyIpv4Envelope(CapturedIpv4Envelope &to, const Ipv4Envelope &from) {
    to = from;
}

}  // namespace tc8
