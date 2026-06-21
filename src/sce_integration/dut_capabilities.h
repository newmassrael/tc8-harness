#pragma once

#include <cstdint>

namespace tc8::sce {

// Which semantic DUT-control sub-interfaces a backend / DUT exposes. Two axes
// are folded into one bitmask:
//   (1) Backend interface surface — which IDutControl sub-interfaces the
//       selected `--dut-control` backend provides (opcode UT is a TC8-tailored
//       superset; AUTOSAR testability is the portable standard subset; the
//       socket backend has no kernel-state probe). Backend-STATIC.
//   (2) DUT firmware fault-injection support — whether the DUT itself
//       implements the UT fault opcode a `_NEG` self-validation case drives.
//       The DUT reports its implemented opcodes via OpQueryCapabilities (0x16,
//       the single source of truth), so a fault cap is DUT-DERIVED, not
//       backend-static: the kernel-stack reference DUT has no fixture fault seam
//       and omits OpSetEgressFlavor / OpSetIngressFlavor, so kCapEgressFault /
//       kCapIngressFault are absent there and the `_NEG` cases capability-skip
//       (N/A); the lwIP fixture implements them and they run.
// A case queries the bit it needs and is capability-skipped (N/A, not a fail)
// when the selected backend / DUT lacks it (test_command.cpp Tier-2 gate). When
// a DUT-derived bit is missing the gate distinguishes "DUT answered, seam
// absent" (legitimate N/A skip) from "could not resolve the DUT's capability
// bitmap" (error, never a silent green) via IDutControl::faultCapsResolved().
//
// This header carries ONLY the enum so a case can declare kRequiredCapabilities
// without pulling the full dut_control.h backend stack (the heavy socket /
// testability / opcode client headers): per the convention in
// test_case_traits.h, the case that sets the member includes the capability
// vocabulary, not the backend implementations.
//
// DUT-derived (axis 2) caps are tracked in kDutDerivedCaps so the gate knows
// which missing bits warrant the "could not resolve" error path; backend-static
// (axis 1) caps are never DUT-derived and a backend that lacks one skips
// honestly.
enum DutCapability : std::uint32_t {
    kCapTcpControl = 1u << 0,        // ITcpControl (handle-based TCP data plane)
    kCapUdpControl = 1u << 1,        // IUdpControl (one-shot UDP send)
    kCapTcpStateProbe = 1u << 2,     // TCP kernel-state query (opcode only)
    kCapArpConditioning = 1u << 3,   // ARP cache conditioning (opcode only)
    kCapLinkLocalControl = 1u << 4,  // link-local autoconf control (opcode only)
    kCapTcpSynSentOpen = 1u << 5,    // active open left in SYN-SENT, non-establishing (opcode only)
    kCapTcpRecvOob = 1u << 6,        // out-of-band (urgent) TCP receive (opcode only)
    kCapEgressFault = 1u << 7,       // egress field fault (OpSetEgressFlavor) — DUT-derived
    kCapIngressFault = 1u << 8,      // ingress prohibited-emission fault (OpSetIngressFlavor) — DUT-derived
};
using DutCapabilities = std::uint32_t;

// The axis-2 (DUT-firmware-derived) subset of DutCapability. A case requiring
// one of these can only be gated after the DUT's OpQueryCapabilities bitmap is
// resolved; if that resolution fails the gate surfaces an error rather than a
// silent N/A skip. Extend alongside every DUT-derived bit added above. The
// dedicated-fault-opcode shape (kCapEgressFault ↔ OpSetEgressFlavor 0x18,
// kCapIngressFault ↔ OpSetIngressFlavor 0x19) is the clean case: a 0x16 per-opcode
// bit is a 1:1 proxy for the whole mechanism. A flavor-byte fault on a
// SHARED opcode (e.g. the DHCPv4 `_neg` flavors on OpStartDhcpClient 0x10) maps
// to its host opcode's presence — sound for applicability (a DUT lacking the
// opcode entirely, like the lwIP fixture for DHCP, correctly skips) but it
// cannot distinguish a DUT that implements the opcode yet ignores the flavor;
// that residual is out of scope until such a DUT exists.
inline constexpr DutCapabilities kDutDerivedCaps = kCapEgressFault | kCapIngressFault;

}  // namespace tc8::sce
