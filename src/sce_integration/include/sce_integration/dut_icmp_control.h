#pragma once

#include <cstdint>
#include <vector>

#include "sce_integration/dut_socket_control.h"

// ICMP sub-interface of the Tier-2 DUT-control seam: make the DUT ORIGINATE an Echo
// Request, which the tester cannot cause from the wire. The Echo Request the DUT emits is
// what a case grades, read from the capture; the answer here says only that the DUT took
// the request, so an E_OK without an emission is the case's to catch (it waits for the
// frame), never trusted.

namespace tc8::sce {

class IIcmpControl {
public:
    virtual ~IIcmpControl() = default;

    // Have the DUT send one ICMPv4 Echo Request carrying `data` to `dest_addr_be`
    // (network byte order), out of the interface its routing picks. kDone when the DUT took
    // the request; kRefused when it answered that it would not; kNoAnswer when the request
    // never came back.
    virtual DutCallOutcome echoRequest(std::uint32_t dest_addr_be,
                                       const std::vector<std::uint8_t> &data) = 0;
};

}  // namespace tc8::sce
