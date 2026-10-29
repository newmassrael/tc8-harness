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
    kCapIngressFault = 1u << 8,      // ingress reaction fault — ARP/ICMP/TCP prohibited emission + UDP acceptance/rejection (OpSetIngressFlavor) — DUT-derived
    kCapAppFault = 1u << 9,          // app-layer reception fault — data-listener discard skip + UI-report corruption (OpSetAppFlavor) — DUT-derived
    kCapEtsFault = 1u << 10,         // SOME/IP application fault — EtsImpl field-getter value corruption (OpSetEtsFlavor) — tc8-dut-only (no lwIP SOME/IP service)
    // DHCP client lifecycle control (IDhcpClientControl) — make the DUT run a
    // DHCP client with a given timing envelope. Backend-STATIC (axis 1): the
    // opcode UT carries OpStartDhcpClient, while PRS_TPSP defines a DHCP group
    // (GID 0x07) whose service primitives this tree has not mined, so the
    // testability backend provides no implementation and a case needing it
    // capability-skips there rather than sitting out its listen window.
    //
    // The `_neg` DHCP flavors ride the SAME opcode with a trailing flavor byte,
    // so this bit maps to host-opcode presence and does not distinguish a DUT
    // that implements the opcode yet ignores a flavor — the shared-opcode
    // residual already stated for kDutDerivedCaps below.
    kCapDhcpClientControl = 1u << 11,
    // IUdpReceiveControl — open DUT UDP receive ports and ask what arrived.
    // Backend-STATIC, and separate from kCapUdpControl because the two
    // directions are independently implementable: the opcode UT carries both,
    // while the testability mapping for the receive question is not settled (see
    // IUdpReceiveControl), so a case needing it skips there rather than sitting
    // out its listen window.
    kCapUdpReceiveControl = 1u << 12,
    // The DUT answers on a SECOND address (`TestConfig::dut.secondary_ip`), which
    // §4.6.5.5 UDP_USER_INTERFACE_07 needs in order to ask it to emit from one.
    //
    // Static like the two above (no DUT I/O), but answered by the TOPOLOGY, not by
    // any backend: both the netns reference DUT and the lwIP fixture speak the
    // same opcode backend, so the backend cannot tell them apart, and the netns
    // pair holds the alias whichever backend reaches the DUT, so no backend may
    // own the answer either. `topologyCapabilities()` reads the address the
    // topology emitted and the gate ORs the bit in beside the backend's word.
    //
    // ⚠ Not a DUT-derived bit. That axis is the OpQueryCapabilities (0x16) bitmap,
    // which is defined over the OPCODE value space — bit (opcode % 8) of byte
    // (opcode / 8) — so it can say which operations a DUT implements and nothing
    // about what addresses it holds. Adding a property there would make the bitmap
    // mean two things (docs/tech-debt.md TD-25).
    kCapSecondaryDutAddress = 1u << 13,
    // ITcpControl::createTcp — a TCP socket created (and optionally bound) but
    // neither connected nor listening: a connection in CLOSED, which RFC 793 3.9
    // CLOSE / ABORT on CLOSED needs. Backend-static: the testability backend maps it
    // to CREATE_AND_BIND alone; the opcode UT opens a socket only by connecting or
    // listening, so it leaves the bit unset and the case skips there.
    kCapTcpCreateClosed = 1u << 14,
    // ITcpControl::sendTcpWithFlags — a send that states PUSH / URGENT (PRS_TPSP
    // SEND_DATA flags). Backend-static: testability carries the flags byte; the
    // opcode OpSendTcpData has none.
    kCapTcpSendFlags = 1u << 15,
    // IServicePrimitiveControl — a service primitive called by group and primitive
    // number, for a DUT that serves primitives of its own. Backend-static: the testability
    // backend frames any primitive; the opcode UT has no such call.
    kCapServicePrimitive = 1u << 16,
    // ISocketConfigControl — set a socket option (TTL, TOS, Nagle, ...) before the traffic
    // under test. Backend-static: the testability backend maps each to CONFIGURE_SOCKET;
    // the opcode UT has no socket-option request.
    kCapSocketConfigure = 1u << 17,
    // IIcmpControl — the DUT originates an ICMPv4 Echo Request. Backend-static: testability
    // ICMP ECHO_REQUEST; the opcode UT has no such request.
    kCapIcmpEcho = 1u << 18,
    // IUdpSocketControl — a UDP socket the case holds between opening and sending (to set an
    // option on it, or to send from one source port more than once). Backend-static:
    // testability CREATE_AND_BIND / SEND_DATA / CLOSE_SOCKET; the opcode UT's UDP is
    // port-based and has only the one-shot IUdpControl send.
    kCapUdpSocket = 1u << 19,
    // The DUT holds an address in a DIFFERENT subnet of its primary interface (RFC 1122
    // §4.1.3.5). A topology fact answered by `topologyCapabilities()` from
    // `dut.second_subnet_ip`, like kCapSecondaryDutAddress and for the same reason, but its own
    // bit: the same-subnet alias cannot show which address a stack chooses as a source, and
    // UDP_USER_INTERFACE_07 relies on that one keeping its meaning.
    kCapSecondSubnetAddress = 1u << 20,
};
using DutCapabilities = std::uint32_t;

// The axis-2 (DUT-firmware-derived) subset of DutCapability. A case requiring
// one of these can only be gated after the DUT's OpQueryCapabilities bitmap is
// resolved; if that resolution fails the gate surfaces an error rather than a
// silent N/A skip. Extend alongside every DUT-derived bit added above. The
// dedicated-fault-opcode shape (kCapEgressFault ↔ OpSetEgressFlavor 0x18,
// kCapIngressFault ↔ OpSetIngressFlavor 0x19) is the clean case: a 0x16 per-opcode
// bit is a 1:1 proxy for the whole mechanism. The one nuance: both OpSetIngressFlavor
// and OpSetAppFlavor now host SEVERAL reaction kinds under a single cap bit —
// OpSetIngressFlavor: ARP / ICMP / TCP prohibited emission + UDP prohibited acceptance /
// rejection; OpSetAppFlavor: data-listener discard skip + UI-report corruption — so a DUT
// advertising the opcode but implementing only some kinds would falsely claim the rest, the
// same residual class as a flavor-byte fault on a SHARED opcode (e.g. the DHCPv4 `_neg`
// flavors on OpStartDhcpClient 0x10): the bit maps to host-opcode presence — sound for
// applicability (a DUT lacking the opcode entirely, like the lwIP fixture for DHCP,
// correctly skips) but it cannot distinguish a DUT that implements the opcode yet ignores a
// flavor. The only ingress-/app-fault DUT is the lwIP fixture, which implements every kind,
// so the residual is out of scope until a DUT implements some but not all.
inline constexpr DutCapabilities kDutDerivedCaps =
    kCapEgressFault | kCapIngressFault | kCapAppFault;

}  // namespace tc8::sce
