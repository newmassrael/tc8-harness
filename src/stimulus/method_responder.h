#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tc8/pollable_service.h"

namespace tc8::stimulus {

// One captured DUT-client Method Request the responder must answer. Carries the
// reply TARGET (`src_ip_be` / `src_port` — the DUT's ephemeral client endpoint,
// known only at capture time) plus the SOME/IP correlation fields a reply echoes
// (the Request ID = client_id + session_id, with the matched service/method) and
// the request payload. Deliberately a leaf value type with
// no sce_integration dependency, so the stimulus layer stays self-contained; an
// OEM reply builder maps it to a `SomeIpRpcMessage` for
// `buildMethodResponse`/`buildMethodError`. Endianness matches `MethodEndpoint`:
// the IPv4 address is network byte order, the port is host order.
struct MethodRequestObservation {
    std::uint32_t src_ip_be = 0;   // DUT client source IPv4 (network byte order) — reply destination.
    std::uint16_t src_port = 0;    // DUT client source UDP port (host order).
    std::uint16_t service_id = 0;
    std::uint16_t method_id = 0;
    std::uint16_t client_id = 0;   // SOME/IP Request ID, high half.
    std::uint16_t session_id = 0;  // SOME/IP Request ID, low half.
    std::vector<std::uint8_t> payload;  // SOME/IP payload (args) after the 16-byte header.
};

// Parse a raw captured L2 frame (`len` bytes) as an Ethernet+IPv4+UDP+SOME/IP
// Method Request addressed to the tester's offered service. Returns the
// observation iff the frame is a well-formed Request (message type 0x00) for
// `service_id`/`method_id` whose UDP destination port is `service_port`;
// std::nullopt otherwise — non-IPv4/UDP, truncated, wrong port, wrong
// service/method, or a RequestNoReturn (0x01, which gets NO reply per
// PRS_SOMEIP_00701). Non-TP only (a single, unsegmented datagram). Pure (no
// I/O), so the match + field extraction are unit-testable without a live socket —
// the same pure/testable split as `buildArpReplyForRequest`.
std::optional<MethodRequestObservation>
parseMethodRequest(const std::uint8_t *frame, std::size_t len, std::uint16_t service_id,
                   std::uint16_t method_id, std::uint16_t service_port);

// Builds the reply bytes for an observed Request — typically
// `buildMethodResponse`/`buildMethodError` of a `SomeIpRpcMessage` whose Message
// ID and Request ID echo the observation. Returns std::nullopt to DECLINE (send
// nothing for this Request — e.g. the case wants silence for a particular
// payload); a present value is sent verbatim. std::optional (rather than an
// empty-vector sentinel) keeps "decline" distinct from a zero-length reply and
// matches the absence idiom of parseMethodRequest / buildArpReplyForRequest.
using MethodReplyBuilder =
    std::function<std::optional<std::vector<std::uint8_t>>(const MethodRequestObservation &)>;

// A background SOME/IP method responder: answers the DUT's Method Requests for
// one (service, method) in-flight, from the tester's offered service port to each
// Request's captured source endpoint. This is the server-role counterpart of
// `ArpResponder` — it closes the "tie the reply primitives together at runtime"
// gap so a tester-as-server case can drive the DUT (in its client role) to issue
// a Request and have the tester reply to the DUT's ephemeral source, which is
// known only once the
// Request is captured. The (service, method) IDs and the reply CONTENT come from
// the caller, so this primitive carries no OEM/NDA payload.
//
// Lifetime + threading model are identical to `ArpResponder` (see that header and
// `tc8/pollable_service.h`): the constructor opens a non-blocking AF_PACKET RX
// socket bound to `iface` (ETH_P_IP, so the kernel pre-filters to IPv4 frames);
// there is NO worker thread — the capture loop folds `pollFd()` into its drain
// set and calls `onReadable()` on the SAME thread as frame dispatch. A case
// builds it in `stimulus()` and hands it to the runner via
// `IBackgroundServiceOwner::adoptService` so it lives across the capture window
// (which opens only after `kickStimulus` returns). Requires CAP_NET_RAW for RX
// (the harness POST_BUILD setcap, same as `sendRawEthernet`); the reply TX goes
// through `emitMethodReply` (a bound UDP socket).
//
// Non-copyable: it owns a live socket fd.
class MethodResponder : public ::tc8::IPollableService {
public:
    // `service_src_port` is the tester's offered service port — both the UDP
    // destination of the Requests this answers AND the source port of the
    // replies (the port the DUT addressed). `builder` runs on the capture thread.
    MethodResponder(std::string_view iface, std::uint16_t service_id, std::uint16_t method_id,
                    std::uint16_t service_src_port, MethodReplyBuilder builder);
    ~MethodResponder();

    MethodResponder(const MethodResponder &) = delete;
    MethodResponder &operator=(const MethodResponder &) = delete;

    // False if the AF_PACKET socket could not be set up. The case checks this
    // before adopting the responder and should surface the failure (inconclusive)
    // rather than assume the DUT's Request will be answered. A !ok() responder
    // reports pollFd() == -1, so the capture loop simply skips it if adopted anyway.
    bool ok() const { return ok_; }

    // tc8::IPollableService — folded into the capture loop's drain set.
    int pollFd() const override { return sock_; }

    // Drain every queued frame, answering each matching Method Request. Runs on
    // the capture-loop thread; non-blocking, returns once drained.
    void onReadable() override;

    // Count of replies emitted so far. Lets a test/case assert the responder
    // actually answered. Written only in onReadable() (the capture thread), so it
    // needs no synchronisation.
    std::uint64_t repliesSent() const { return replies_sent_; }

private:
    std::string iface_;
    std::uint16_t service_id_;
    std::uint16_t method_id_;
    std::uint16_t service_src_port_;
    MethodReplyBuilder builder_;
    int sock_ = -1;
    bool ok_ = false;
    std::uint64_t replies_sent_ = 0;
};

}  // namespace tc8::stimulus
