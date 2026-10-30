#pragma once

#include <array>
#include <cstdint>

// ARP-plane sub-interface of the Tier-2 DUT-control seam: the things a §4.2
// case needs the DUT to DO, as opposed to the ARP frames the tester injects.
//
// Its own header, beside the DHCP and link-local ones, for the same reason: the
// ~56 ARP case headers that need the vocabulary should not pull the socket
// sub-interfaces to get it.

namespace tc8::sce {

// Make the DUT change state on its ARP plane that the tester cannot write from
// the wire: age its cache, install or take out a permanent entry. Provoking the
// DUT to originate traffic, so that its own ARP resolution becomes observable, is
// not here: that is a UDP send (IUdpControl::sendDatagram), and a backend that
// can send a datagram but has no ARP cache control can still provoke.
class IArpControl {
public:
    virtual ~IArpControl() = default;

    // Age the DUT's dynamic ARP entries by `seconds` (§4.2.4.2 ARP_48/49), so a
    // case can reach the part of an entry's life it asserts on without waiting
    // it out. Only a DUT that implements the conditioning operation can answer; a
    // backend without it is absent rather than silently ineffective, so the gate
    // can skip honestly. A typed operation and not an action code: the opcode
    // UT's action numbers are its own, and another backend (a registered
    // extension) answers this in its own terms.
    virtual int ageCacheBySeconds(std::uint16_t seconds) = 0;

    // Install / take out a permanent ARP entry on the DUT: the configuration and
    // cleanup operations of TC8 §4.2.3. The entry is named explicitly by the case —
    // typically its own tester address and the MAC it wants the DUT to use — and
    // never implied by the backend from where the control request came from.
    // A non-zero return means the DUT did not install (or remove) it; the backend
    // records that as an unperformed stimulus, so a case that goes on to assert
    // "no ARP Request" cannot pass or fail on an entry that was never there.
    virtual int addStaticEntry(std::uint32_t ip_be, const std::array<std::uint8_t, 6> &mac) = 0;
    virtual int removeStaticEntry(std::uint32_t ip_be) = 0;
};

}  // namespace tc8::sce
