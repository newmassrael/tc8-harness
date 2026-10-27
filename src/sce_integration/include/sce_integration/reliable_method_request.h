#pragma once

#include <memory>
#include <vector>

#include "sce_integration/stimulus_context.h"
#include "stimulus/reliable_method_session.h"

namespace tc8::sce {

// Send `requests` (one write; several are one TCP segment) on a tester connection to
// the DUT reliable endpoint `dest`, and hand the connection to the runner, which holds
// it until teardown. For a case that fails on a reliable Response's absence: the
// Response can only come back on the connection its Request used, so that connection
// must outlive the window the state machine measures (stimulus/reliable_method_session.h).
//
// A connection or a write that fails is recorded by the session as an unperformed
// stimulus (stimulus/tx_observer.h, reportTxFailed), so the run is inconclusive rather
// than a Response's absence the tester caused. Returns whether the requests went out.
inline bool sendOnHeldReliableConnection(StimulusContext &ctx,
                                         const ::tc8::stimulus::Endpoint &dest,
                                         const std::vector<::tc8::stimulus::SomeIpRpcMessage> &requests) {
    auto session = std::make_unique<::tc8::stimulus::ReliableMethodSession>(ctx.iface, dest);
    const bool sent = session->valid() && session->send(requests) == 0;
    // Adopted either way: a connection whose write failed is still the runner's to close.
    ctx.services.adoptService(std::move(session));
    return sent;
}

}  // namespace tc8::sce
