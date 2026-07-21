#pragma once

#include <cstdint>

namespace tc8 {

// Shared L3 source/destination address surface for every SCE Named
// Context that records the IPv4 envelope of an observed frame (SOME/IP,
// UDP, TCP, DHCPv4, ICMPv4). Owns the two network-byte-order address
// words — defined ONCE so the field type, the NBO convention, and the
// zero default cannot drift across protocols.
//
// Data only. The protocol-specific address predicates stay in their
// derived structs because their spec citations and comparison semantics
// are protocol-specific (e.g. `Dhcpv4Captured::source_ip_is_zero()` /
// `dst_ip_is_broadcast()` / `dst_ip_equals()` carry their own RFC 2131
// references, and the `TcpCaptured` quad matchers fold in
// `expected.dut_iface_ip`); they read these inherited members unchanged.
//
// Inherited (not composed as a nested member) so SCXML conditions keep
// the single-dot `cpp:captured.dst_ip == ...` form that SCE's expression
// rewriter requires — it rewrites `captured.X` into `this->captured_->X`
// but not `captured.X.Y` (see reference_sce_captured_arg.md). Through a
// derived pointer, inherited member access stays single-dot, so the
// rewrite applies uniformly.
//
// The type has only data and no user-declared constructors, so a Captured
// struct that derives from it remains an aggregate under C++17, keeping
// the existing `c{}` value-initialisation and POD copy semantics intact.
// It shares no common ancestor with `CapturedPayloadSnapshot`,
// `CapturedFrameTiming`, or `CapturedL4Ports`, so a context deriving from
// several carries independent data-only subobjects with no diamond.
struct CapturedL3Endpoints {
    std::uint32_t src_ip = 0;  // network byte order
    std::uint32_t dst_ip = 0;  // network byte order
};

}  // namespace tc8
