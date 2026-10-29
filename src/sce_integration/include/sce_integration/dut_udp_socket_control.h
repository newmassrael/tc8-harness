#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "sce_integration/dut_socket_control.h"

// Handle-based UDP of the Tier-2 DUT-control seam: open a UDP socket on the DUT, use it, close
// it. The one-shot IUdpControl::sendDatagram opens, sends and closes in one call, which is the
// right shape for a backend whose UDP model is port-based (the opcode UT) and the wrong one
// for a case that has to do something to the socket between opening it and sending: set an
// option (ISocketConfigControl::configureUdp), or send several datagrams from one source port.
//
// A separate sub-interface, not three more verbs on IUdpControl: a backend that provides the
// one-shot send need not provide a socket, and the capability gate has to be able to say so
// (kCapUdpSocket). The testability backend provides both; the opcode UT only the one-shot.

namespace tc8::sce {

class IUdpSocketControl {
public:
    virtual ~IUdpSocketControl() = default;

    // Open a UDP socket on the DUT bound to `local` (`local.addr_be == 0` is the DUT's default
    // address for the egress interface, `local.port == 0` an ephemeral port). nullopt when the
    // DUT could not.
    virtual std::optional<DutSocket> openUdp(const Endpoint &local) = 0;

    // Send `data` to `dest` from the socket. kDone when the DUT sent it; kRefused when the DUT
    // answered that it would not; kNoAnswer when the request never came back.
    virtual DutCallOutcome sendUdp(DutSocket sock, const Endpoint &dest,
                                   const std::vector<std::uint8_t> &data) = 0;

    // Close the socket. A socket a case opened and did not close is the backend's to reap at
    // end of test, as for TCP.
    virtual DutCallOutcome closeUdp(DutSocket sock) = 0;
};

}  // namespace tc8::sce
