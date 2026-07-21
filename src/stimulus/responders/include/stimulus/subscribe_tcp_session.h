#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "stimulus/endpoint.h"           // Endpoint — DUT reliable endpoint (SSOT).
#include "stimulus/someip_sd_builder.h"  // SubscribeEventgroupTarget / SubscribeDestination.
#include "tc8/pollable_service.h"        // IPollableService — capture-loop drain contract.

namespace tc8::stimulus {

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

    // Dual-transport variant of subscribe(): advertise BOTH a UDP endpoint
    // (the tester's SD port — where unreliable notifications and the Ack are
    // delivered) AND this session's held TCP endpoint (option 1, l4proto 0x06).
    // A mixed-reliability (RT_BOTH) eventgroup NACKs a single-option Subscribe
    // and, in vsomeip 3.7.x, further requires the advertised TCP endpoint to
    // have an ESTABLISHED connection — which this session holds — before it
    // Acks. Use this for a Subscribe to eg 0x0002 (which carries reliable
    // 0x8003 mixed with the unreliable events); use subscribe() only for a
    // reliable-only eventgroup where a single TCP option suffices.
    int subscribeDual(const SubscribeEventgroupTarget &target, const SubscribeDestination &sd_dest = {});

    // Flexible dual-transport Subscribe: take a caller-built `params` (custom
    // session_id / ttl / sd_flags / a distinct advertised UDP endpoint) and
    // inject THIS session's held TCP endpoint as option 1 before emitting. The
    // UDP option (option 0) defaults to this session's source SD endpoint when
    // `params.tester_endpoint.ipv4_be` is zero; a case advertising a distinct
    // endpoint pre-fills it. subscribeDual() is the Target-only convenience
    // wrapper over this. Used by the multi-Subscribe / distinct-endpoint cases.
    int subscribeDualParams(SubscribeEventgroupParams params, const SubscribeDestination &sd_dest = {});

    // Emit a caller-built Subscribe from THIS session's source IP (so vsomeip
    // binds it to the held connection), filling option 0 with the session's UDP
    // SD endpoint only when the caller left it unset. Unlike subscribeDualParams
    // it does NOT touch the entry's option-run config — a case with a bespoke
    // dual layout (e.g. ETS_173's two option runs) sets `second_endpoint =
    // reliableEndpointOption()` plus its own index/count and calls this.
    int subscribeParams(SubscribeEventgroupParams params, const SubscribeDestination &sd_dest = {});

    // The IPv4 Endpoint option (l4proto TCP) for this session's held reliable
    // connection — the option a bespoke dual Subscribe puts in
    // `params.second_endpoint`. valid() must be true.
    Ipv4Endpoint reliableEndpointOption() const {
        return Ipv4Endpoint{src_ip_be_, local_port_, 0x06};
    }

    // Dual-transport MULTI-entry Subscribe: emit one SD message bundling
    // `entries` (each a distinct eventgroup) advertising a UDP option + THIS
    // session's held TCP endpoint (option 1); every entry references both. A
    // bundle that includes a mixed-reliability eventgroup (eg 0x0002) needs the
    // held connection for vsomeip to Ack that entry. Used by the multi-entry
    // mixed-eventgroup Subscribe case.
    int subscribeMultiDual(const std::vector<SubscribeEventgroupTarget> &entries,
                           const SubscribeDestination &sd_dest = {});

    // Flexible multi-entry dual Subscribe: emit a caller-built bundle from THIS
    // session's source IP, injecting the held TCP endpoint as option 1. The
    // caller sets per_entry_num_options_first so a mixed-reliability entry
    // references UDP + TCP (#Opt1=2) while unreliable entries reference UDP only
    // (#Opt1=1) — the reference bundle shape. subscribeMultiDual is the wrapper
    // that references both options for every entry.
    int subscribeMultiParams(MultiSubscribeEventgroupParams params,
                             const SubscribeDestination &sd_dest = {});

    // Abortive close (transport-level teardown): force a RST (SO_LINGER 0 + close)
    // so the DUT sees the connection reset and is expected to delete the reliable
    // subscription — the "connection refused" teardown shape. The socket is gone
    // afterwards: pollFd() returns -1 and the session cannot subscribe or receive
    // again. This operates only on the session's OWN socket (no packet filter); the
    // silent "connection lost" (half-open) teardown is a NETWORK-policy concern that
    // lives in the sce layer (tcp_pilot_common.h TesterInboundDropScope), keyed on
    // the 4-tuple below — not on this transport object. No in-tree case exercises
    // either teardown yet; the DUT-side deletion is the intended mechanism.
    void refuseWithRst();

    // The connection's endpoints — the DUT reliable endpoint this session connected
    // to (for a reconnect or a second session) and the tester's own endpoint (the
    // 4-tuple an sce-layer drop filter targets to tear this connection down).
    const Endpoint &dutReliable() const { return dut_reliable_; }
    Endpoint testerEndpoint() const { return Endpoint{src_ip_be_, local_port_}; }

    // IPollableService.
    int pollFd() const override { return fd_; }
    void onReadable() override;

  private:
    int fd_ = -1;
    std::uint32_t src_ip_be_ = 0;  // this session's source IPv4 (NBO) — bound + advertised.
    std::string iface_;
    std::uint16_t local_port_ = 0;  // host order.
    Endpoint dut_reliable_{};        // DUT reliable endpoint (for teardown filter + reconnect).
};

}  // namespace tc8::stimulus
