#pragma once

#include <cstdint>
#include <vector>

#include "sce_integration/dut_socket_control.h"

// Socket-option sub-interface of the Tier-2 DUT-control seam: the options a case sets on a
// DUT socket before the traffic it grades, backend-neutral.
//
// A case names an option in this vocabulary, never a protocol's parameter id. The
// testability backend maps each option to its CONFIGURE_SOCKET parameter (PRS_TPSP
// §6.10.10); a backend with another way to set it maps it its own way, and a backend that
// cannot says so, and the case skips (kCapSocketConfigure) instead of grading a socket
// that was never configured.
//
// What the DUT answered is a DutCallOutcome, so the decorator (RecordingDutControl) accounts
// it like every other DUT-control action: a refusal or an unsupported option under the
// default intent is a stimulus that did not take, and the run ends inconclusive with the
// option named in the record.

namespace tc8::sce {

enum class SocketOption : std::uint8_t {
    kTtl,           // IP time to live of the socket's datagrams / segments; value 0..255
    kTos,           // IPv4 type-of-service byte (DSCP + ECN); value 0..255
    kNagle,         // TCP Nagle algorithm; value 1 = enabled, 0 = disabled (TCP only)
    kUdpChecksum,   // transmit a UDP checksum; value 1 = yes, 0 = no (UDP only)
    kDontFragment,  // IP Don't-Fragment bit; value 1 = set, 0 = clear
    kMss,           // TCP maximum segment size; value 500..1460 (TCP only)
};

// The option's name as it appears in a record or a report.
inline const char *socketOptionName(SocketOption option) {
    switch (option) {
        case SocketOption::kTtl:          return "ttl";
        case SocketOption::kTos:          return "tos";
        case SocketOption::kNagle:        return "nagle";
        case SocketOption::kUdpChecksum:  return "udp_checksum";
        case SocketOption::kDontFragment: return "dont_fragment";
        case SocketOption::kMss:          return "mss";
    }
    return "unknown";
}

class ISocketConfigControl {
public:
    virtual ~ISocketConfigControl() = default;

    // Set `option` on the DUT's TCP socket `sock`. kDone when the DUT applied it;
    // kRefused(kUnsupported) when the DUT does not serve the option, kRefused(kOther) when
    // it served it and said no (a malformed value, a stack that cannot); kNoAnswer when
    // the request never came back.
    virtual DutCallOutcome configureTcp(DutSocket sock, SocketOption option,
                                        std::uint32_t value) = 0;

    // The same for a UDP socket the case opened through IUdpSocketControl (the one-shot
    // IUdpControl::sendDatagram has no socket to configure). The outcomes are as above.
    virtual DutCallOutcome configureUdp(DutSocket sock, SocketOption option,
                                        std::uint32_t value) = 0;
};

}  // namespace tc8::sce
