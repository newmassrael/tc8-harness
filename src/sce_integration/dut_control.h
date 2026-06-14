#pragma once

#include <cassert>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "sce_integration/dut_socket_control.h"
#include "stimulus/testability_client.h"
#include "stimulus/upper_tester_client.h"
#include "tc8/testability_protocol.h"
#include "tc8/upper_tester_protocol.h"

namespace tc8::sce {

// Which semantic DUT-control sub-interfaces a backend exposes. Backends and
// real DUTs differ (opcode UT is a TC8-tailored superset; AUTOSAR testability
// is the portable standard subset), so a case queries the bit it needs and is
// conditioning-skipped when the selected backend lacks it.
enum DutCapability : std::uint32_t {
    kCapTcpControl = 1u << 0,        // ITcpControl (handle-based TCP data plane)
    kCapUdpControl = 1u << 1,        // IUdpControl (one-shot UDP send)
    kCapTcpStateProbe = 1u << 2,     // TCP kernel-state query (opcode only)
    kCapArpConditioning = 1u << 3,   // ARP cache conditioning (opcode only)
    kCapLinkLocalControl = 1u << 4,  // link-local autoconf control (opcode only)
    kCapTcpSynSentOpen = 1u << 5,    // active open left in SYN-SENT, non-establishing (opcode only)
};
using DutCapabilities = std::uint32_t;

// Upper-Tester-channel abstraction so the harness can drive either an in-house
// opcode DUT (the reference tc8-dut / lwIP DUT) or a standard AUTOSAR
// Testability Protocol DUT behind one handle.
//
// The interface captures the genuinely cross-cutting contract — UT-channel
// liveness plus the test-session lifecycle. The session lifecycle is exactly
// what the standard protocol ADDS over the opcode protocol: testability frames
// START_TEST / END_TEST (PRS_TPSP §6.10), whereas the opcode protocol has no
// session framing and relies on per-case DUT respawn. A backend-agnostic
// driver can therefore bracket a case with startTest()/endTest() and get the
// right behaviour on either DUT. Protocol-specific stimulus (opcode requests
// vs typed service primitives) stays on the concrete backend — see
// TestabilityControl::call() for the standard generic engine.
//
// Existing cases do not use this seam; they call the opcode builders directly
// and are unaffected. It is the entry point for out-of-tree OEM cases and for
// `tc8-harness testability-probe`.
class IDutControl {
public:
    virtual ~IDutControl() = default;

    // Is the UT channel reachable? (opcode: OpPing; testability: GET_VERSION.)
    virtual bool probe() = 0;

    // Begin a test session. Opcode backend: no-op (returns true) — the
    // in-house protocol has no session frame and isolates via respawn.
    // Testability backend: START_TEST (GENERAL/0x02).
    virtual bool startTest() = 0;

    // End / reset a test session. Opcode backend: no-op. Testability backend:
    // END_TEST (GENERAL/0x03) — closes sockets, clears buffers.
    virtual bool endTest() = 0;

    // Human-readable backend tag for diagnostics / probe output.
    virtual const char *backendName() const = 0;

    // Which semantic sub-interfaces this backend exposes (DutCapability bits).
    virtual DutCapabilities capabilities() const = 0;

    // Data-plane sub-interfaces, or nullptr when unsupported — a case checks for
    // nullptr and conditioning-skips. Default nullptr: a backend opts in by
    // overriding once it implements the sub-interface.
    virtual ITcpControl *tcpControl() { return nullptr; }
    virtual IUdpControl *udpControl() { return nullptr; }

    // Kernel-state probe — opcode-only (no standard testability SP reads kernel
    // TCP state). nullptr on a backend without it; a case declaring
    // kCapTcpStateProbe is capability-skipped there (Tier 2 2b#4).
    virtual ITcpStateProbe *tcpStateProbe() { return nullptr; }
};

// Seam-case convenience: fetch the DUT's TCP control sub-interface as a
// reference, asserting it is present. A seam TCP case has already been
// conditioning-skipped by the centralised capability gate (Tier 2 2b#4) when
// the selected backend lacks kCapTcpControl, so the pointer is non-null by
// contract; returning a reference encodes that at the call site (callers use
// `.`) and the assert documents the invariant. Collapses the tcpControl()-deref
// + null-assert idiom the seam helpers (active / passive / listen / send)
// otherwise repeat.
inline ITcpControl &seamTcpControl(IDutControl &dut) {
    ITcpControl *tcp = dut.tcpControl();
    assert(tcp != nullptr && "seam TCP cases require kCapTcpControl");
    return *tcp;
}

// Opcode-UT backend of ITcpControl — a synchronous SOCK_DGRAM round-trip
// adapter over the opcode builders. The opcode UT server answers every request
// on the bound socket, so the AF_PACKET inject path the cases use is not needed
// here. Active open maps to OpOpenTcpSocket(Active); passive open is
// OpOpenTcpSocket(Passive) + an OpQueryTcpEstablished poll (the opcode model
// reports acceptance as a boolean and does not surface the client endpoint).
class OpcodeTcpControl final : public ITcpControl {
public:
    OpcodeTcpControl(std::uint32_t dut_ip_be, std::uint16_t port, std::uint32_t src_ip_be,
                     int timeout_ms)
        : dut_ip_be_(dut_ip_be), port_(port), src_ip_be_(src_ip_be), timeout_ms_(timeout_ms) {}

    std::optional<DutConnection> connectTcp(const Endpoint &peer,
                                            const BindSpec &local) override {
        const auto r = stimulus::upperTesterRoundTrip(
            dut_ip_be_,
            stimulus::buildOpenTcpSocketActiveRequest(nextReqId(), opcodeLocalPort(local),
                                                      peer.addr_be, peer.port),
            port_, timeout_ms_, src_ip_be_);
        if (!r || r->status != ut::kStatusOk || r->data.empty()) {
            return std::nullopt;
        }
        return DutConnection{DutSocket{r->data[0]}, peer};
    }

    std::optional<DutConnection> acceptTcp(const BindSpec &listen,
                                           const std::function<void()> &trigger) override {
        // Accept = listen, then await acceptance. The passive open is the
        // listenTcp() seam (single source of the OpOpenTcpSocket(Passive)
        // round trip); acceptTcp adds the trigger + the OpQueryTcpEstablished
        // poll the listen-only verb omits.
        const auto listen_sock = listenTcp(listen);
        if (!listen_sock) {
            return std::nullopt;
        }
        if (trigger) {
            trigger();
        }
        // Poll until the listener reports acceptance — the opcode UT's
        // boolean-progress model, no async event.
        for (int i = 0; i < kAcceptPolls; ++i) {
            const auto q = stimulus::upperTesterRoundTrip(
                dut_ip_be_,
                stimulus::buildQueryTcpEstablishedRequest(
                    nextReqId(), static_cast<std::uint8_t>(listen_sock->id)),
                port_, timeout_ms_, src_ip_be_);
            if (q && q->status == ut::kStatusOk && !q->data.empty() && q->data[0] != 0) {
                // OpQueryTcpEstablished does not return the client endpoint.
                return DutConnection{*listen_sock, Endpoint{}};
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(kAcceptPollMs));
        }
        return std::nullopt;
    }

    std::optional<DutSocket> listenTcp(const BindSpec &listen) override {
        // OpOpenTcpSocket(Passive) leaves the DUT listening and returns the
        // listener socket id at once. acceptTcp() builds on this and adds the
        // OpQueryTcpEstablished poll; a listen-only caller drives and observes
        // its own (handshake-incomplete) stimulus instead of awaiting an accept.
        const auto open = stimulus::upperTesterRoundTrip(
            dut_ip_be_,
            stimulus::buildOpenTcpSocketPassiveRequest(nextReqId(), opcodeLocalPort(listen)),
            port_, timeout_ms_, src_ip_be_);
        if (!open || open->status != ut::kStatusOk || open->data.empty()) {
            return std::nullopt;
        }
        return DutSocket{open->data[0]};
    }

    bool sendTcp(DutSocket sock, const std::vector<std::uint8_t> &data) override {
        // OpSendTcpData (0x06): literal payload, capped at kMaxPayload (256 B).
        const auto r = stimulus::upperTesterRoundTrip(
            dut_ip_be_,
            stimulus::buildSendTcpDataRequest(nextReqId(), static_cast<std::uint8_t>(sock.id),
                                              data.empty() ? nullptr : data.data(),
                                              static_cast<std::uint16_t>(data.size())),
            port_, timeout_ms_, src_ip_be_);
        return r && r->status == ut::kStatusOk;
    }

    bool sendTcpPattern(DutSocket sock, std::uint8_t pattern,
                        std::uint16_t total_len) override {
        // OpSendTcpDataPattern (0x0A): the DUT generates total_len bytes from a
        // single pattern byte, past the OpSendTcpData literal-payload cap.
        const auto r = stimulus::upperTesterRoundTrip(
            dut_ip_be_,
            stimulus::buildSendTcpDataPatternRequest(
                nextReqId(), static_cast<std::uint8_t>(sock.id), pattern, total_len),
            port_, timeout_ms_, src_ip_be_);
        return r && r->status == ut::kStatusOk;
    }

    bool shutdownTcpWr(DutSocket sock) override {
        // OpShutdownTcpSocketWr (0x08): shutdown(SHUT_WR) — kernel FIN, EST->FW1,
        // read side open (PRS_TPSP §6.10 SHUTDOWN typeId=0x01 counterpart).
        const auto r = stimulus::upperTesterRoundTrip(
            dut_ip_be_,
            stimulus::buildShutdownTcpSocketWrRequest(nextReqId(),
                                                      static_cast<std::uint8_t>(sock.id)),
            port_, timeout_ms_, src_ip_be_);
        return r && r->status == ut::kStatusOk;
    }

    bool closeTcp(DutSocket sock) override {
        const auto r = stimulus::upperTesterRoundTrip(
            dut_ip_be_,
            stimulus::buildCloseTcpSocketRequest(nextReqId(), static_cast<std::uint8_t>(sock.id)),
            port_, timeout_ms_, src_ip_be_);
        return r && r->status == ut::kStatusOk;
    }

private:
    std::uint8_t nextReqId() { return req_id_++; }

    // Map the seam BindSpec's local endpoint onto the opcode protocol's single
    // local-port slot (the active/passive OPEN take one port; 0 == DUT-chosen
    // ephemeral). The seam follows the PRS_TPSP convention — PORT_ANY is
    // spelled 0xFFFF and binding is gated on do_bind — so an unbound spec OR an
    // explicit PORT_ANY both collapse to 0. This keeps the documented
    // "local_port 0xFFFF == PORT_ANY" BindSpec contract identical on this
    // backend and the testability one (whose server maps 0xFFFF -> 0). The
    // opcode OPEN has no local-addr slot (the DUT sources its iface IP), so
    // BindSpec::local_addr_be is deliberately not represented here.
    static std::uint16_t opcodeLocalPort(const BindSpec &b) {
        return (b.do_bind && b.local_port != 0xFFFF) ? b.local_port : 0;
    }

    static constexpr int kAcceptPolls = 20;
    static constexpr int kAcceptPollMs = 25;  // up to ~500 ms for the accept

    std::uint32_t dut_ip_be_;
    std::uint16_t port_;
    std::uint32_t src_ip_be_;
    int timeout_ms_;
    std::uint8_t req_id_ = 1;
};

// Opcode-UT backend of ITcpStateProbe — synchronous OpQueryTcpEstablished
// (0x05) and OpQueryTcpInfo (0x13) round-trips over the bound UT socket. No
// AUTOSAR testability counterpart (the standard exposes no kernel-state SP), so
// this sub-interface gates kCapTcpStateProbe.
class OpcodeTcpStateProbe final : public ITcpStateProbe {
public:
    OpcodeTcpStateProbe(std::uint32_t dut_ip_be, std::uint16_t port, std::uint32_t src_ip_be,
                        int timeout_ms)
        : dut_ip_be_(dut_ip_be), port_(port), src_ip_be_(src_ip_be), timeout_ms_(timeout_ms) {}

    std::optional<bool> isEstablished(DutSocket sock) override {
        const auto r = stimulus::upperTesterRoundTrip(
            dut_ip_be_,
            stimulus::buildQueryTcpEstablishedRequest(nextReqId(),
                                                      static_cast<std::uint8_t>(sock.id)),
            port_, timeout_ms_, src_ip_be_);
        if (!r || r->status != ut::kStatusOk || r->data.empty()) {
            return std::nullopt;
        }
        return r->data[0] != 0;
    }

    std::optional<DutTcpInfo> queryInfo(DutSocket sock) override {
        const auto r = stimulus::upperTesterRoundTrip(
            dut_ip_be_,
            stimulus::buildQueryTcpInfoRequest(nextReqId(), static_cast<std::uint8_t>(sock.id)),
            port_, timeout_ms_, src_ip_be_);
        // Body: <state:u8> <rto_us:u32 BE> <retransmits:u8> <unacked:u32 BE> = 10 B.
        if (!r || r->status != ut::kStatusOk || r->data.size() < 10) {
            return std::nullopt;
        }
        const auto &d = r->data;
        DutTcpInfo info{};
        info.state       = d[0];
        info.rto_us      = (static_cast<std::uint32_t>(d[1]) << 24) |
                           (static_cast<std::uint32_t>(d[2]) << 16) |
                           (static_cast<std::uint32_t>(d[3]) << 8) |
                           static_cast<std::uint32_t>(d[4]);
        info.retransmits = d[5];
        info.unacked     = (static_cast<std::uint32_t>(d[6]) << 24) |
                           (static_cast<std::uint32_t>(d[7]) << 16) |
                           (static_cast<std::uint32_t>(d[8]) << 8) |
                           static_cast<std::uint32_t>(d[9]);
        return info;
    }

private:
    std::uint8_t nextReqId() { return req_id_++; }

    std::uint32_t dut_ip_be_;
    std::uint16_t port_;
    std::uint32_t src_ip_be_;
    int timeout_ms_;
    std::uint8_t req_id_ = 1;
};

// Adapter over the in-house opcode Upper Tester (upper_tester_client.h). Wraps
// the existing builders/transport with no behaviour change. Kernel-routed
// SOCK_DGRAM probe (matching `ut-ping`); the TCP data plane is exposed through
// OpcodeTcpControl and the kernel-state probe through OpcodeTcpStateProbe. UDP
// through the seam stays on the direct TriggerSendUdp path (port-based, no
// handle), so kCapUdpControl is not set here.
class OpcodeUtControl final : public IDutControl {
public:
    explicit OpcodeUtControl(std::uint32_t dut_ip_be, std::uint16_t port = ut::kPort,
                             std::uint32_t src_ip_be = 0, int timeout_ms = 1000)
        : dut_ip_be_(dut_ip_be), port_(port), src_ip_be_(src_ip_be), timeout_ms_(timeout_ms),
          tcp_ctrl_(dut_ip_be, port, src_ip_be, timeout_ms),
          state_probe_(dut_ip_be, port, src_ip_be,
                       timeout_ms < kStateProbeTimeoutMs ? timeout_ms : kStateProbeTimeoutMs) {}

    bool probe() override {
        return stimulus::pingUpperTester(dut_ip_be_, port_, timeout_ms_, src_ip_be_)
            .has_value();
    }
    // The opcode protocol has no session framing — per-case respawn provides
    // isolation, so the lifecycle calls are well-defined no-ops.
    bool startTest() override { return true; }
    bool endTest() override { return true; }
    const char *backendName() const override { return "opcode-ut"; }

    DutCapabilities capabilities() const override {
        return kCapTcpControl | kCapTcpStateProbe | kCapTcpSynSentOpen;
    }
    ITcpControl *tcpControl() override { return &tcp_ctrl_; }
    ITcpStateProbe *tcpStateProbe() override { return &state_probe_; }

private:
    // Fail-fast ceiling for the kernel-state probe, independent of the
    // control-plane timeout. The TCP retransmission-timeout cluster polls
    // queryInfo() inside tight phase deadlines (e.g. SYN-RTO cases give
    // ~2 s to observe a retransmit at +1 s); a stalled query that blocked
    // the full control-plane timeout would burn most of that window and
    // starve the loop of retry attempts. 500 ms matches the proven
    // ceiling the pre-seam direct TCP_INFO probe used so poll loops fail a
    // dropped probe quickly and re-poll. Capped by min semantics so a
    // caller that sets an even shorter control timeout still wins.
    static constexpr int kStateProbeTimeoutMs = 500;

    std::uint32_t dut_ip_be_;
    std::uint16_t port_;
    std::uint32_t src_ip_be_;
    int timeout_ms_;
    OpcodeTcpControl tcp_ctrl_;
    OpcodeTcpStateProbe state_probe_;
};

// Adapter over the AUTOSAR Testability Protocol client (testability_client.h).
// Besides the IDutControl lifecycle it exposes the protocol's generic
// `call(gid, pid, dat)` engine, which OEM-specific typed service-primitive
// wrappers (written out of tree) build on.
class TestabilityControl final : public IDutControl {
public:
    explicit TestabilityControl(const stimulus::TestabilityConfig &cfg, int timeout_ms = 1000,
                                std::uint32_t src_ip_be = 0)
        : cfg_(cfg), timeout_ms_(timeout_ms), src_ip_be_(src_ip_be),
          tcp_ctrl_(cfg, timeout_ms, src_ip_be), udp_ctrl_(cfg, timeout_ms, src_ip_be) {}

    bool probe() override { return getVersion().has_value(); }
    bool startTest() override {
        return stimulus::testabilityStartTest(cfg_, timeout_ms_, src_ip_be_).eok();
    }
    bool endTest() override {
        return stimulus::testabilityEndTest(cfg_, /*tc_id=*/0, "tc8-harness", timeout_ms_,
                                            src_ip_be_)
            .eok();
    }
    const char *backendName() const override { return "autosar-testability"; }

    // The standard socket SPs (CREATE_AND_BIND/CONNECT/LISTEN_AND_ACCEPT/
    // SEND_DATA/CLOSE_SOCKET) are all implemented, so both data-plane
    // sub-interfaces are available on every testability DUT.
    DutCapabilities capabilities() const override { return kCapTcpControl | kCapUdpControl; }
    ITcpControl *tcpControl() override { return &tcp_ctrl_; }
    IUdpControl *udpControl() override { return &udp_ctrl_; }

    // GET_VERSION (GENERAL/0x01).
    std::optional<stimulus::TestabilityVersion> getVersion() {
        return stimulus::testabilityGetVersion(cfg_, timeout_ms_, src_ip_be_);
    }

    // Generic service-primitive call — the OEM-specific extension surface
    // (non-standard SPs build on this directly).
    stimulus::TestabilityResponse call(std::uint8_t gid, std::uint8_t pid,
                                       const std::vector<std::uint8_t> &dat = {}) {
        return stimulus::testabilityCall(cfg_, gid, pid, dat, timeout_ms_, src_ip_be_);
    }

    // Standard typed service primitives are NOT re-exposed here: they are the
    // free functions in testability_client.h (the single source of truth for SP
    // wire encoding), invoked with config(). The case-facing seam for
    // protocol-agnostic DUT operations belongs on IDutControl as semantic
    // operations, not as protocol-specific SP forwarders — see that interface.
    const stimulus::TestabilityConfig &config() const { return cfg_; }

private:
    stimulus::TestabilityConfig cfg_;
    int timeout_ms_;
    std::uint32_t src_ip_be_;
    TestabilityTcpControl tcp_ctrl_;
    TestabilityUdpControl udp_ctrl_;
};

}  // namespace tc8::sce
