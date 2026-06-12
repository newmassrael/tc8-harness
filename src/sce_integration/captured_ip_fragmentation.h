#pragma once

#include <cstdint>

namespace tc8 {

// Shared "carrying IP datagram fragmentation" surface for the SCE Named
// Contexts that observe an L4 datagram and keep the encapsulating IPv4
// header's fragmentation state: UDP (the IPv4_FRAGMENTS_05 case asserts a
// DUT-emitted datagram carries MF=0 / offset=0) and DHCPv4 (carries the
// same envelope knobs for symmetry). Owns the 3-bit Flags byte and the
// 13-bit Fragment Offset — defined ONCE so the field type and the zero
// default cannot drift between the two borrowers.
//
// Deliberately NOT inherited by Ipv4Captured. That context represents a
// whole observed IPv4 header as a cohesive unit and names these fields
// natively (`flags` / `fragment_offset`) alongside ten sibling header
// fields. Folding it into this mixin would (a) fragment that cohesive
// header for a two-field gain, and (b) force its `captured.flags` SCXML
// conds to rename — entangled with TcpCaptured, which also exposes a
// `flags` member, so the rename could not be done by spelling alone. The
// `flags` (native header field) vs `ip_flags` (borrowed envelope field)
// distinction is intentional, not drift.
//
// Inherited (not composed as a nested member) so SCXML conditions keep
// the single-dot `cpp:captured.ip_flags == ...` form that SCE's
// expression rewriter requires — it rewrites `captured.X` into
// `this->captured_->X` but not `captured.X.Y` (see
// reference_sce_captured_arg.md).
//
// Data only, no user-declared constructors: a derived Captured struct
// stays a C++17 aggregate, and shares no common ancestor with the other
// Captured mixins, so a multi-base context carries independent data-only
// subobjects with no diamond.
struct CapturedIpFragmentation {
    std::uint8_t  ip_flags           = 0;   // carrying IP header's 3-bit Flags
    std::uint16_t ip_fragment_offset = 0;   // carrying IP header's 13-bit offset
};

}  // namespace tc8
