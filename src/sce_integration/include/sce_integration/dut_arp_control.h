#pragma once

#include <array>
#include <cstdint>

#include "stimulus/boot_timing.h"

// ARP-plane sub-interface of the Tier-2 DUT-control seam: the things a §4.2
// case needs the DUT to DO, as opposed to the ARP frames the tester injects.
//
// Its own header, beside the DHCP and link-local ones, for the same reason: the
// ~56 ARP case headers that need the vocabulary should not pull the socket
// sub-interfaces to get it.
//
// The provocation's envelope is `stimulus::BootTiming`, the type the cases and
// `TestConfig::stimulus_timing` already speak. Minting a second struct with the
// same three fields would only create something to keep in step.

namespace tc8::sce {

// Make the DUT act on its ARP plane. Neither operation is reachable from the
// wire: the provocation asks the DUT to ORIGINATE traffic so that its own ARP
// resolution becomes observable, and cache conditioning asks it to change state
// the tester cannot write.
class IArpControl {
public:
    virtual ~IArpControl() = default;

    // Provoke DUT egress so its ARP request/reply behaviour can be observed.
    // Returns the underlying send's status: 0 on success, negative otherwise —
    // the shape the ARP cases already branch on.
    virtual int provokeEgress(const ::tc8::stimulus::BootTiming &timing) = 0;

    // Condition the DUT's ARP cache (§4.2.4.2 ARP_48/49). Only a DUT that
    // implements the conditioning opcode can answer; a backend without it is
    // absent rather than silently ineffective, so the gate can skip honestly.
    virtual int conditionCache(std::uint8_t action, std::uint16_t param) = 0;

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
