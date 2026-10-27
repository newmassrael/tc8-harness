#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "stimulus/endpoint.h"            // Endpoint — the DUT reliable endpoint (SSOT).
#include "stimulus/someip_rpc_builder.h"  // SomeIpRpcMessage, buildMethodRequest.
#include "tc8/pollable_service.h"         // IPollableService — capture-loop drain contract.

namespace tc8::stimulus {

// A tester-owned TCP connection to a DUT reliable endpoint that carries SOME/IP
// Method Requests and stays open for the whole run, so every Response the DUT
// sends back travels a connection the tester still holds.
//
// Why it exists: a reliable Method Response can only reach the tester on the
// connection the Request came in on. A request helper that closes its socket a
// fixed time after the send (emitMethodRequestTcpAfter's linger) grants the DUT
// that linger, not the listen time the case grades: once the tester's FIN is out,
// a later Response meets a closed connection, and a case that fails on the
// Response's absence would be grading the tester's close. Held here, the
// connection lasts until run teardown, so the window the state machine measures
// is the window the DUT actually had.
//
// A case builds it during stimulus(), sends on it, and hands ownership to the
// runner via `IBackgroundServiceOwner::adoptService`. The runner closes it (RAII)
// at teardown and calls onReadable() on each drain, which reads and discards the
// inbound bytes: the verdict is taken from the capture, and draining keeps the
// receive window open (tc8/pollable_service.h).
class ReliableMethodSession : public ::tc8::IPollableService {
  public:
    // Connect from `iface`'s primary IPv4 (ephemeral source port) to `dut_reliable`.
    // On failure valid() is false and the cause is logged; pollFd() is then -1, so
    // the capture loop skips the session. A case records the failure as an
    // unperformed stimulus: nothing it sends afterwards reaches the DUT.
    ReliableMethodSession(std::string_view iface, const Endpoint &dut_reliable);
    ~ReliableMethodSession() override;

    ReliableMethodSession(const ReliableMethodSession &) = delete;
    ReliableMethodSession &operator=(const ReliableMethodSession &) = delete;

    bool valid() const { return fd_ >= 0; }

    // Send the Method Requests built from `requests`, back to back in ONE write
    // (buildBundledMethodRequests), each with its session_id as given. One request is
    // the ordinary case; several are the "several SOME/IP messages in one TCP segment"
    // stimulus. Returns 0, or a negative value when the session is invalid (-1) or the
    // write did not take every byte (-5), which is logged.
    int send(const std::vector<SomeIpRpcMessage> &requests);

    // IPollableService. -1 once the DUT has closed the connection: an fd at
    // end-of-stream stays readable, and polling it would wake the loop every pass.
    int pollFd() const override { return peer_closed_ ? -1 : fd_; }
    void onReadable() override;

  private:
    int           fd_          = -1;
    bool          peer_closed_ = false;
    std::string   iface_;
    Endpoint      dut_reliable_{};
};

}  // namespace tc8::stimulus
