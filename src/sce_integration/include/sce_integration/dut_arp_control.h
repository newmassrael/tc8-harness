#pragma once

#include <array>
#include <cstdint>

// ARP-plane sub-interfaces of the Tier-2 DUT-control seam: the things a §4.2
// case needs the DUT to DO, as opposed to the ARP frames the tester injects.
//
// Their own header, beside the DHCP and link-local ones, for the same reason: the
// ~56 ARP case headers that need the vocabulary should not pull the socket
// sub-interfaces to get it.
//
// TWO interfaces, each behind its own capability bit, because a DUT can serve one
// without the other: a static neighbour add and remove is an ordinary
// configuration operation, while "age every dynamic entry by N seconds" is a
// conformance-fixture operation most stacks do not expose (a reachable-time setting
// is a different operation). Under one interface and one bit, a provider serving
// only the static half had to claim the aging half too, which would un-skip the
// aging cases on a DUT that cannot age, or claim nothing and leave its own cases
// skipped. A claim covers exactly what the provider answers, so the seam is split
// where the operations are.
//
// Provoking the DUT to originate traffic, so that its own ARP resolution becomes
// observable, is in neither: that is a UDP send (IUdpControl::sendDatagram), and a
// backend that can send a datagram but has no ARP-plane control can still provoke.

namespace tc8::sce {

// Age the DUT's dynamic ARP entries (kCapArpCacheAging).
class IArpCacheAging {
public:
    virtual ~IArpCacheAging() = default;

    // Age the DUT's dynamic ARP entries by `seconds` (§4.2.4.2 ARP_48/49), so a
    // case can reach the part of an entry's life it asserts on without waiting
    // it out. Only a DUT that implements the conditioning operation can answer; a
    // backend without it is absent rather than silently ineffective, so the gate
    // can skip honestly. A typed operation and not an action code: the opcode
    // UT's action numbers are its own, and another backend (a registered
    // extension) answers this in its own terms. Non-zero means not done.
    virtual int ageCacheBySeconds(std::uint16_t seconds) = 0;
};

// Install and take out a permanent ARP entry on the DUT (kCapArpStaticEntry): the
// configuration and cleanup operations of TC8 §4.2.3.
class IArpStaticEntry {
public:
    virtual ~IArpStaticEntry() = default;

    // The entry is named explicitly by the case — typically its own tester address
    // and the MAC it wants the DUT to use — and never implied by the backend from
    // where the control request came from. A non-zero return means the DUT did not
    // install (or remove) it; the backend records that as an unperformed stimulus,
    // so a case that goes on to assert "no ARP Request" cannot pass or fail on an
    // entry that was never there.
    //
    // ⚠ A provider must still HEAR the DUT after the install: the entry maps the
    // tester's address to a MAC no tester interface owns, so every later reply is
    // addressed to that MAC. Over a kernel-routed control channel the tester's own
    // kernel drops it as another host's frame, and the install's acknowledgement is
    // the first casualty. Both reference backends answer at L2 when they have a wire.
    virtual int addStaticEntry(std::uint32_t ip_be, const std::array<std::uint8_t, 6> &mac) = 0;
    virtual int removeStaticEntry(std::uint32_t ip_be) = 0;
};

}  // namespace tc8::sce
