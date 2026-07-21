#pragma once

#include <cstdint>

namespace tc8 {

// Shared L4 source/destination port surface for every SCE Named Context
// that records the transport ports of an observed frame (SOME/IP, UDP,
// TCP, DHCPv4). Owns the two host-byte-order port words — defined ONCE so
// the field type, the host-order convention, and the zero default cannot
// drift across protocols. (The wire is big-endian; the dissector and the
// UT-region builders normalise to host order on the way in, which is why
// `udp_captured.h` re-serialises with an explicit `>> 8` / `& 0xFF` split
// rather than a raw copy.)
//
// Data only. The protocol-specific port guards stay in their derived
// structs / SCXML conditions (e.g. SOME/IP `src_port == SERVICE-ID-1 UDP
// port`, UDP's `src_port == ut::kPort` UT gate); they read these
// inherited members unchanged.
//
// Inherited (not composed as a nested member) so SCXML conditions keep
// the single-dot `cpp:captured.src_port == ...` form that SCE's
// expression rewriter requires — it rewrites `captured.X` into
// `this->captured_->X` but not `captured.X.Y` (see
// reference_sce_captured_arg.md). Through a derived pointer, inherited
// member access stays single-dot, so the rewrite applies uniformly.
//
// The type has only data and no user-declared constructors, so a Captured
// struct that derives from it remains an aggregate under C++17, keeping
// the existing `c{}` value-initialisation and POD copy semantics intact.
// It shares no common ancestor with `CapturedPayloadSnapshot`,
// `CapturedFrameTiming`, or `CapturedL3Endpoints`, so a context deriving
// from several carries independent data-only subobjects with no diamond.
struct CapturedL4Ports {
    std::uint16_t src_port = 0;  // host byte order
    std::uint16_t dst_port = 0;  // host byte order
};

}  // namespace tc8
