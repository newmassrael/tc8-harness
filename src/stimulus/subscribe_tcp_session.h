#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "stimulus/endpoint.h"           // Endpoint — DUT reliable endpoint (SSOT).
#include "stimulus/someip_sd_builder.h"  // SubscribeEventgroupTarget / SubscribeDestination.
#include "tc8/pollable_service.h"        // IPollableService — capture-loop drain contract.

namespace tc8::stimulus {

// How a reliable-subscribe session tears its connection down so the DUT deletes
// the subscription: the DUT stops delivering the reliable event once it detects
// the connection is gone.
enum class TcpTeardownMode {
    // Half-open: silently DROP the DUT's inbound segments so the tester kernel
    // stops ACKing; the DUT's send stalls and its half-open detection deletes the
    // subscription. No FIN/RST leaves the tester — the "connection lost" shape.
    // Reversible via resumeIncoming().
    kDropIncoming,
    // Refuse: force a RST so the DUT sees the connection reset and deletes the
    // subscription — the "connection refused" shape. Not reversible on the same
    // connection (the socket is gone after the RST).
    kRefuseWithRst,
};

// A tester-owned RELIABLE (TCP) eventgroup subscription session — the live-TCP
// counterpart of the UDP `emitSubscribeEventgroupBoot` family. It is what lets a
// case observe (and later assert the absence of) a reliable event such as
// TestEventUINT8Reliable (0x8003) that the DUT delivers only over TCP.
//
// Delivery is CLIENT-INITIATED. On a remote subscription vsomeip normalises the
// subscriber's reliable endpoint to the server's OWN reliable port
// (routing_manager_impl `set_remote_port(get_reliable_port(...))`) and pushes
// notifications back over the tcp_server_endpoint connection the subscriber
// opened — the same path the reliable Method Response travels (RPC_17 /
// `emitMethodRequestTcpAndHold`), NOT a server-initiated connect-out. So this
// session:
//   1. opens and HOLDS a TCP connection from `iface` to the DUT reliable
//      endpoint (its ephemeral source port is the connection identity),
//   2. emits one SubscribeEventgroup over the SD UDP port whose IPv4 Endpoint
//      option advertises THIS connection's TCP endpoint (l4proto 0x06), so the
//      DUT binds the reliable subscription to the held connection, and
//   3. stays alive across the capture window as an `IPollableService` so the DUT
//      keeps delivering notifications over it — the wire pcap sees each one and
//      the SM verdicts it.
//
// A case builds it during stimulus() and hands ownership to the runner via
// `IBackgroundServiceOwner::adoptService`; the runner keeps the fd open for the
// whole run (RAII close at teardown) and calls onReadable() each capture-loop
// iteration. onReadable() drains inbound event bytes — the verdict is
// wire-capture based, so the bytes are discarded; draining only keeps the
// receive window open and consumes any pending socket error (the busy-spin
// contract in `tc8/pollable_service.h`).
class SubscribeEventgroupTcpSession : public ::tc8::IPollableService {
  public:
    // Open a tester-owned TCP socket and connect it to `dut_reliable` (the DUT's
    // reliable endpoint, e.g. `tc8::sce::someipTcpMethodDest(cfg)`), holding it
    // open. The socket binds an ephemeral source port on `source_ip_be` — pass a
    // configured secondary/alias tester IP (network byte order) to originate a
    // SECOND client from a distinct source IP (so the DUT holds two independent
    // reliable subscriptions), or the default 0 to use `iface`'s primary IPv4. The
    // chosen source IP is what the Subscribe option advertises, so the DUT tracks
    // the two clients apart. On
    // failure valid() is false and the errno is logged; pollFd() then returns -1 so
    // the capture loop skips the session (it is still owned and torn down normally).
    SubscribeEventgroupTcpSession(std::string_view iface, const Endpoint &dut_reliable,
                                  std::uint32_t source_ip_be = 0);
    ~SubscribeEventgroupTcpSession() override;

    SubscribeEventgroupTcpSession(const SubscribeEventgroupTcpSession &) = delete;
    SubscribeEventgroupTcpSession &operator=(const SubscribeEventgroupTcpSession &) = delete;

    bool valid() const { return fd_ >= 0; }

    // The tester's local TCP source port (host order) advertised in the Subscribe
    // option — the connection identity the DUT binds the reliable subscription
    // to. 0 when the session is invalid.
    std::uint16_t localPort() const { return local_port_; }

    // Emit ONE SubscribeEventgroup for `target` over the SD UDP port (30490),
    // advertising this session's TCP endpoint (iface IPv4 : localPort(),
    // l4proto 0x06) so the DUT delivers `target.eventgroup_id`'s reliable events
    // over the held connection. `sd_dest` is the DUT's SD endpoint (derive from
    // cfg; the default matches the bundled tc8-dut). Returns 0 on success or a
    // negative errno-derived sentinel (-1 if the session is invalid).
    int subscribe(const SubscribeEventgroupTarget &target, const SubscribeDestination &sd_dest = {});

    // --- Teardown controls (OEM-enabling seam) ---
    //
    // Tear the connection down so the DUT is expected to delete the reliable
    // subscription and stop delivering the event: a consuming case observes the
    // reliable event live, calls one of these, then verifies no further event.
    // NOTE: no in-tree case exercises these yet — the reliable-teardown cases are
    // out-of-tree (OEM) — so the DUT-side deletion below is the INTENDED mechanism,
    // not one an in-tree test asserts.

    // Connection-lost shape: install a kernel packet-filter rule that DROPs the
    // DUT's inbound segments on THIS connection, so the tester stops ACKing and the
    // DUT's send is intended to stall into half-open detection. No FIN/RST is
    // emitted. Idempotent; removed by resumeIncoming() or at destruction. Needs the
    // netns-root context the smoke test runs in; a failed install is logged and
    // left non-fatal (the case then observes a timeout rather than silence).
    void dropIncoming();
    // Remove the dropIncoming() filter so the tester resumes ACKing.
    void resumeIncoming();

    // Connection-refused shape: force a RST (SO_LINGER 0 + close) so the DUT sees
    // the connection reset. The socket is gone afterwards — pollFd() returns -1 and
    // the session cannot subscribe or receive again.
    void refuseWithRst();

    // Dispatch to the mode's control (kDropIncoming -> dropIncoming, kRefuseWithRst
    // -> refuseWithRst) — the seam a teardown driver uses without branching.
    void applyTeardown(TcpTeardownMode mode);

    // The DUT reliable endpoint this session connected to (for a reconnect
    // observer or a second session), and the tester's advertised endpoint.
    const Endpoint &dutReliable() const { return dut_reliable_; }

    // IPollableService.
    int pollFd() const override { return fd_; }
    void onReadable() override;

  private:
    int fd_ = -1;
    std::uint32_t src_ip_be_ = 0;  // this session's source IPv4 (NBO) — bound + advertised.
    std::string iface_;
    std::uint16_t local_port_ = 0;  // host order.
    Endpoint dut_reliable_{};        // DUT reliable endpoint (for teardown filter + reconnect).
    bool drop_installed_ = false;    // a dropIncoming() filter is currently installed.
};

}  // namespace tc8::stimulus
