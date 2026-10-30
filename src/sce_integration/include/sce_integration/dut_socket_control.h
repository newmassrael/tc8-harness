#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "tc8/dut_listen_backlog.h"
#include "tc8/testability_client.h"
#include "tc8/testability_protocol.h"

namespace tc8::sce {

// Tier 2 data-plane seam (see docs/dut_control_seam.md).
//
// The backend-agnostic vocabulary cases use to drive the DUT's socket data
// plane. Split by protocol (ISP): the TCP side is handle-based (open returns a
// socket the caller threads to send/close) and maps cleanly onto both the
// opcode UT and AUTOSAR testability; the UDP side is a one-shot send (the
// opcode UT's TriggerSendUdp is port-based, not handle-based, so a unified
// handle interface would not fit it). A backend implements whichever
// sub-interfaces it supports and toggles the matching capability bit;
// operations only one backend can do (TCP kernel-state query, ARP
// conditioning, link-local) live on their own sub-interfaces, not here.
//
// Handles are opaque: a `DutSocket` is an id the backend issued; the seam does
// not encode the protocol group (the backend tracks what it needs internally).

struct Endpoint {
    std::uint32_t addr_be = 0;  // IPv4, network byte order
    std::uint16_t port = 0;
};

// CREATE_AND_BIND parameters (PRS_TPSP §6.10): bind to (local_addr_be,
// local_port) when do_bind; local_port 0xFFFF == PORT_ANY, local_addr_be 0 ==
// INADDR_ANY.
struct BindSpec {
    bool do_bind = false;
    std::uint16_t local_port = 0xFFFF;
    std::uint32_t local_addr_be = 0;
};

// Opaque DUT socket handle.
struct DutSocket {
    std::uint16_t id = 0;
};

// An established/accepted TCP connection on the DUT: the connection's socket
// plus the remote endpoint (for passive open, the accepted client's address).
struct DutConnection {
    DutSocket socket;
    Endpoint peer;
};

// The request bits of a TCP send (PRS_TPSP §6.10 SEND_DATA flags).
struct TcpSendFlags {
    bool push = false;    // PSH: deliver without waiting for more data
    bool urgent = false;  // URG: the last byte of the send is urgent
};

// The answer a DUT-control call got, in three outcomes a bool cannot tell apart:
// the DUT did it; the DUT answered that it would not (and why, in backend-neutral
// terms); or no answer came, which says nothing about the DUT. A case that grades
// the answer itself (RFC 793 3.9: CLOSE or ABORT on a connection that does not
// exist must be refused) needs the refusal and its reason, and must not mistake a
// lost request for one.
struct DutCallOutcome {
    enum class Kind : std::uint8_t { kDone, kRefused, kNoAnswer };
    enum class Refusal : std::uint8_t {
        kNone,                    // not refused
        kConnectionDoesNotExist,  // the socket names no connection the DUT holds
        kUnsupported,             // the DUT does not serve what was asked (an option it lacks)
        kOther,                   // refused for any other reason
    };

    Kind kind = Kind::kNoAnswer;
    Refusal refusal = Refusal::kNone;

    static DutCallOutcome done() { return {Kind::kDone, Refusal::kNone}; }
    static DutCallOutcome refused(Refusal why) { return {Kind::kRefused, why}; }
    static DutCallOutcome noAnswer() { return {Kind::kNoAnswer, Refusal::kNone}; }

    bool isDone() const { return kind == Kind::kDone; }
};

// The answer to a RECEIVE: the bytes the DUT's application got, a refusal (the
// Upper Tester answered that the receive failed), or no answer. A case grading the
// DUT's delivery reads `data` only when answered; a refusal is also the DUT's
// answer (it did not deliver); no answer says nothing about the DUT, and the
// decorator records it as an unperformed stimulus.
struct DutReceiveOutcome {
    DutCallOutcome::Kind kind = DutCallOutcome::Kind::kNoAnswer;
    std::vector<std::uint8_t> data;  // what RECEIVE returned, when kDone

    static DutReceiveOutcome received(std::vector<std::uint8_t> bytes) {
        return {DutCallOutcome::Kind::kDone, std::move(bytes)};
    }
    static DutReceiveOutcome refused() { return {DutCallOutcome::Kind::kRefused, {}}; }
    static DutReceiveOutcome noAnswer() { return {DutCallOutcome::Kind::kNoAnswer, {}}; }

    bool answered() const { return kind != DutCallOutcome::Kind::kNoAnswer; }
    // The DUT returned exactly `expected`.
    bool returned(const std::vector<std::uint8_t> &expected) const {
        return kind == DutCallOutcome::Kind::kDone && data == expected;
    }
};

// Handle-based TCP data plane — both backends support it.
class ITcpControl {
public:
    virtual ~ITcpControl() = default;

    // Active open: the DUT connects to `peer` (the caller's listener),
    // optionally binding a specific local endpoint first (`local.do_bind`).
    // Cases whose guard pins the DUT's source port need the bind (standard
    // CREATE_AND_BIND + CONNECT); the default (`do_bind=false`) leaves the
    // local endpoint to the DUT (ephemeral port, route-chosen source IP).
    // Returns the DUT's connected socket, or nullopt on failure.
    //
    // The `= {}` default is declared here ONLY (not on the overrides) per C++
    // Core Guidelines C.140 — a default on a virtual is resolved by the static
    // type, so duplicating it on overriders invites silent divergence. Callers
    // through `ITcpControl` get the ephemeral-local default; the overrides take
    // the parameter plain.
    virtual std::optional<DutConnection> connectTcp(const Endpoint &peer,
                                                    const BindSpec &local = {}) = 0;
    // Passive open: the DUT binds+listens per `listen`; `trigger` drives one
    // inbound connection once the DUT is listening; returns the accepted
    // connection (with the client endpoint when the backend reports it), or
    // nullopt if none arrived.
    //
    // Trigger call-count contract: `trigger` is invoked AT MOST ONCE — exactly
    // once on the path that reaches the accept, and not at all when the bind /
    // listen / arm setup fails before that point (the nullopt failure paths).
    // It is never invoked more than once. A trigger may therefore consume
    // captured state by move (e.g. hand a crafted SYN's options vector to the
    // handshake without copying). `receiveTcp` shares this contract; every
    // override must honour it.
    virtual std::optional<DutConnection> acceptTcp(const BindSpec &listen,
                                                   const std::function<void()> &trigger) = 0;
    // Passive open WITHOUT awaiting accept: the DUT binds+listens per `listen`
    // and is left in the LISTEN state. Unlike acceptTcp, the caller drives its
    // own tester-side stimulus (raw SYNs / invalid segments) and observes the
    // DUT's wire responses — for cases that never complete a kernel handshake
    // (SYN met with RST, or left in SYN-RCVD), where acceptTcp's accept
    // confirmation would never arrive. Returns the listening socket handle (for
    // a later closeTcp), or nullopt on failure.
    virtual std::optional<DutSocket> listenTcp(const BindSpec &listen) = 0;
    // Create (and bind, when local.do_bind) a socket that neither connects nor
    // listens: a connection in CLOSED, for RFC 793 3.9 CLOSE / ABORT on CLOSED.
    // testability CREATE_AND_BIND alone. A backend that cannot returns nullopt and
    // leaves kCapTcpCreateClosed unset, so a case needing it skips.
    virtual std::optional<DutSocket> createTcp(const BindSpec &local) = 0;
    // Transmit exactly `data` on the connected socket — a literal send
    // (opcode OpSendTcpData / testability SEND_DATA with totalLen == size).
    // For a bulk fill past the literal-payload cap use sendTcpPattern.
    virtual bool sendTcp(DutSocket sock, const std::vector<std::uint8_t> &data) = 0;
    // Make the DUT emit `total_len` bytes formed by repeating the single byte
    // `pattern` — a bulk/fill send for the MSS / segmentation / window tests
    // whose byte content is not load-bearing. Both backends generate the bytes
    // DUT-side so the request stays compact and bypasses the opcode literal
    // cap: opcode OpSendTcpDataPattern, testability SEND_DATA with a one-byte
    // template repeated to total_len (PRS_TPSP §6.10). Split from sendTcp so
    // each verb is a total function both backends implement faithfully (the
    // opcode pattern op repeats one byte; folding it into sendTcp's total_len
    // would make sendTcp a partial function on the opcode backend).
    virtual bool sendTcpPattern(DutSocket sock, std::uint8_t pattern,
                                std::uint16_t total_len) = 0;
    // A literal send that also states the request bits a case grades: PUSH (RFC
    // 1122 4.2.2.2, PRS_TPSP SEND_DATA flags bit 3) and URGENT (bit 5, the
    // urgent pointer at the last byte). Its own verb because only the testability
    // backend can say it: the opcode OpSendTcpData has no flags field, so that
    // backend returns false and does not advertise kCapTcpSendFlags, and a case
    // needing it skips there. A plain sendTcp promises neither bit either way.
    virtual bool sendTcpWithFlags(DutSocket sock, const std::vector<std::uint8_t> &data,
                                  TcpSendFlags flags) = 0;
    // Receive up to `max_len` bytes the DUT has on `sock`. `trigger` drives the
    // inbound data (e.g. inject a tester segment): the testability backend ARMS
    // RECEIVE_AND_FORWARD before invoking trigger so the forwarded bytes are
    // captured, while the opcode backend invokes trigger then queries
    // OpReceiveTcpData (its kernel already queued the bytes). Returns the bytes
    // the DUT received (<= max_len; empty when it received none), a refusal when
    // the Upper Tester answered that the RECEIVE failed, or no answer when the
    // request never came back — the at-most-once `trigger` call-count contract of
    // acceptTcp, which the arm-then-trigger control flow mirrors.
    virtual DutReceiveOutcome receiveTcp(DutSocket sock, std::uint16_t max_len,
                                         const std::function<void()> &trigger) = 0;
    // Half-close the write direction: the DUT calls shutdown(SHUT_WR) on the
    // socket — the kernel emits FIN (EST -> FIN-WAIT-1) while the read side
    // stays open so a later receive still drains inbound bytes. Distinct from
    // closeTcp's full ::close: the socket lives on for reads (the
    // "CLOSE then RECEIVE" lifecycle of the FIN-WAIT-1/-2 receive cases).
    // opcode OpShutdownTcpSocketWr, testability
    // SHUTDOWN typeId=0x01 (PRS_TPSP §6.10). WR-only: the opcode UT exposes no
    // SHUT_RD/SHUT_RDWR primitive, so a general shutdownTcp(type) would be a
    // partial function on that backend; the dedicated WR verb stays a total
    // function on both. Add RD/RDWR verbs if a case ever needs them (YAGNI).
    virtual bool shutdownTcpWr(DutSocket sock) = 0;
    // Close a TCP socket gracefully (FIN).
    virtual DutCallOutcome closeTcp(DutSocket sock) = 0;
    // Abortive close: the DUT closes the socket immediately with a RST (no
    // graceful FIN), not waiting for outstanding transmissions/acknowledgements —
    // the application ABORT primitive (RFC 793 §3.9). opcode OpAbortTcpSocket
    // (SO_LINGER {1,0} + close), testability CLOSE_SOCKET with the abort flag set
    // (PRS_TPSP §6.10 CLOSE_SOCKET abort param). Split from closeTcp's graceful
    // ::close so each verb is a total function both backends implement faithfully.
    // Both return the typed outcome (DutCallOutcome), because "the DUT refused" is
    // an answer a case may grade and "no answer" is not.
    virtual DutCallOutcome abortTcp(DutSocket sock) = 0;
};

// One-shot UDP send — no handle, matching the opcode UT's port-based model.
class IUdpControl {
public:
    virtual ~IUdpControl() = default;

    // Make the DUT emit one UDP datagram from `src` to `dest` carrying `data`.
    // true on success.
    //
    // The source is an Endpoint rather than a bare port so the local ADDRESS is
    // expressible: `src.addr_be == 0` means "the DUT's default address for the
    // egress interface" (the only shape the opcode UT's TriggerSendUdp used
    // before this seam existed), and a non-zero value requests that specific
    // source address — the caller-specified Source IP axis a UDP user-interface
    // case drives when it must observe which address the DUT originates from.
    // Both backends can honour it: the opcode envelope carries a source-IP
    // override field, and the testability path binds the address at
    // CREATE_AND_BIND. A backend that could not would return false rather than
    // silently send from the default, because a datagram from the wrong source
    // address answers a different question than the one that was asked.
    virtual bool sendDatagram(const Endpoint &src, const Endpoint &dest,
                              const std::vector<std::uint8_t> &data) = 0;

    // As sendDatagram, but returns once the request has left the tester, without
    // waiting for the DUT's reply. For a case whose point is that the DUT cannot
    // reply yet: it holds a cold ARP cache for the tester, so its answer to the
    // request is queued behind the very resolution the case then provokes, and
    // waiting for it would wait for something only the case's next step produces.
    // The cost is that a request the DUT never applied is not noticed here, which
    // is why a case uses it only when the wire shows the effect (the datagram the
    // DUT was asked to send). A backend whose protocol cannot send without a
    // reply (testability: the socket id comes from a response) returns false, and
    // the case is gated on kCapUdpUnacknowledgedSend so it is skipped there.
    virtual bool sendDatagramUnacknowledged(const Endpoint &src, const Endpoint &dest,
                                            const std::vector<std::uint8_t> &data) = 0;
};

// One datagram the DUT's UDP socket delivered to its application.
struct DutReceivedDatagram {
    Endpoint source;                    // who sent it (address, port)
    std::uint16_t full_len = 0;         // its true length, forwarded or not
    std::vector<std::uint8_t> payload;  // the bytes the DUT reported (<= the arm's max_fwd)
};

// The payload of the well-formed datagram a receive window sends after the probe
// (see IUdpReceiveControl::receiveUdp). Defined with the seam, not by the helper
// that sends it, so a backend recognises the sentinel by the same bytes the
// sender used and a probe can never be mistaken for one.
inline constexpr std::array<std::uint8_t, 8> kUdpReceiveSentinelPayload{'T', 'C', '8', '-',
                                                                        'S', 'N', 'T', 'L'};

// What one receive window observed on the DUT's UDP socket.
//
// `datagrams` are the datagrams the socket delivered during the window, in arrival
// order, the sentinel left out. `path_proven` says the backend demonstrated that
// its receive path worked across the window. It is what turns an empty list into
// an OBSERVED discard instead of a silence: a forward loop that is dead delivers
// nothing, exactly as a DUT that dropped the probe does, and only a datagram that
// was meant to arrive and did separates the two.
struct DutUdpReceiveOutcome {
    DutCallOutcome::Kind kind = DutCallOutcome::Kind::kNoAnswer;
    std::vector<DutReceivedDatagram> datagrams;
    bool path_proven = false;

    static DutUdpReceiveOutcome noAnswer() { return {}; }
    static DutUdpReceiveOutcome refused() {
        DutUdpReceiveOutcome o;
        o.kind = DutCallOutcome::Kind::kRefused;
        return o;
    }
    static DutUdpReceiveOutcome observed(std::vector<DutReceivedDatagram> datagrams,
                                         bool path_proven) {
        DutUdpReceiveOutcome o;
        o.kind = DutCallOutcome::Kind::kDone;
        o.datagrams = std::move(datagrams);
        o.path_proven = path_proven;
        return o;
    }

    bool answered() const { return kind != DutCallOutcome::Kind::kNoAnswer; }
    // The socket delivered the probe: a datagram arrived, so the path worked.
    bool received() const { return kind == DutCallOutcome::Kind::kDone && !datagrams.empty(); }
    // The probe did not arrive and the path is proven live: the DUT discarded it.
    bool discarded() const {
        return kind == DutCallOutcome::Kind::kDone && datagrams.empty() && path_proven;
    }
};

// The RECEIVE direction of the DUT's UDP data plane: open listening ports, and
// observe what arrives on one.
//
// A separate sub-interface rather than two more methods on IUdpControl, because
// a backend can provide one direction and not the other and the gate has to be
// able to say so.
class IUdpReceiveControl {
public:
    virtual ~IUdpReceiveControl() = default;

    // Have the DUT open `count` UDP receive ports, and report how many it opened.
    // nullopt when the request got no answer or was refused; a count below
    // `count` is the DUT's answer that it could not open them all, which is the
    // finding the case grades.
    virtual std::optional<std::uint8_t> createReceivePorts(std::uint8_t count) = 0;

    // Observe what the DUT's socket on `listen` receives while `probe` runs.
    // `listen.port` is the port under test. `listen.addr_be` scopes the opcode
    // backend's receipt log to datagrams sent to that destination (0 = any); the
    // testability backend binds the port on any address, so that the sentinel,
    // which goes to the DUT's unicast address, proves the path even when the probe
    // went to an address the DUT is expected to refuse.
    // `probe` sends the datagram under test; `sentinel` sends one well-formed
    // datagram (kUdpReceiveSentinelPayload) to the same endpoint and is called
    // after `probe`, at most once. The arm-then-trigger shape ITcpControl::
    // receiveTcp has: a backend that must be listening BEFORE the datagram
    // arrives arms first, and one whose kernel already queued it asks after.
    //
    // A backend whose answer to "did you receive it" is affirmative (the opcode
    // UT says received=0) has no use for the sentinel and does not call it. A
    // backend that only reports what arrived (testability RECEIVE_AND_FORWARD)
    // calls it after the probe: the sentinel arrives or the path is not proven,
    // and the premise is one the socket keeps, that its receive queue preserves
    // arrival order, so a sentinel delivered after the probe means a probe that
    // reached the socket would already have been delivered.
    //
    // The outcome is kRefused when the DUT answered that it could not listen, and
    // kNoAnswer when no answer came, which says nothing about the DUT.
    virtual DutUdpReceiveOutcome receiveUdp(const Endpoint &listen,
                                            const std::function<void()> &probe,
                                            const std::function<void()> &sentinel) = 0;
};

// Live kernel TCP_INFO snapshot of a DUT socket. Mirrors the four fields the
// TCP retransmission-timeout cluster verdicts on (getsockopt(SOL_TCP,
// TCP_INFO)).
struct DutTcpInfo {
    std::uint8_t  state       = 0;  // tcpi_state (1=ESTABLISHED, 2=SYN_SENT, ...)
    std::uint32_t rto_us      = 0;  // tcpi_rto (microseconds)
    std::uint8_t  retransmits = 0;  // tcpi_retransmits
    std::uint32_t unacked     = 0;  // tcpi_unacked (tp->packets_out)
};

// The RFC 793 state of a DUT socket, as a DUT reports it.
//
// `kOtherThanEstablished` is for a DUT that can say a socket is NOT in
// ESTABLISHED and cannot name the state it is in (the opcode UT's establishment
// query is a yes/no question). A case that needs a named state declares a bit a
// backend can honour only when it names them; one that needs only establishment
// compares against kEstablished and is indifferent to the rest.
enum class DutTcpState : std::uint8_t {
    kClosed,
    kListen,
    kSynSent,
    kSynReceived,
    kEstablished,
    kFinWait1,
    kFinWait2,
    kCloseWait,
    kClosing,
    kLastAck,
    kTimeWait,
    kOtherThanEstablished,
};

// TCP connection-state query — which RFC 793 state a DUT socket is in. No
// standard AUTOSAR testability service primitive exposes it (the standard
// surface is connection lifecycle + data, not introspection), so a backend that
// cannot answer returns nullptr from IDutControl::tcpStateQuery(), and a case
// that declares kCapTcpStateQuery is capability-skipped on that backend rather
// than failed (Tier 2 2b#4) — the honest expression of the standard's limit. A
// DUT that serves the query through a registered extension provides it here
// without having to answer TCP_INFO. See docs/dut_control_seam.md.
class ITcpStateQuery {
public:
    virtual ~ITcpStateQuery() = default;

    // The state of the DUT's socket, or nullopt on query failure (the case
    // treats that as a third answer, distinct from established and not).
    virtual std::optional<DutTcpState> queryState(DutSocket sock) = 0;
};

// Kernel TCP_INFO probe — the retransmission-timeout, retransmit count and
// unacked counters of a DUT socket. Opcode-only for the same reason as
// ITcpStateQuery and a separate sub-interface because a DUT can answer one
// question and not the other: a backend that answers the state alone must not
// claim this one, or the retransmission cases would run into nullopt instead of
// skipping. Gated by kCapTcpInfoProbe.
class ITcpInfoProbe {
public:
    virtual ~ITcpInfoProbe() = default;

    // Live TCP_INFO snapshot of the DUT's socket, or nullopt on query failure.
    virtual std::optional<DutTcpInfo> queryInfo(DutSocket sock) = 0;
};

// Whether an answered state query says ESTABLISHED. nullopt (the query failed)
// stays nullopt, so a case keeps its third answer.
inline std::optional<bool> isEstablished(const std::optional<DutTcpState> &state) {
    if (!state.has_value()) {
        return std::nullopt;
    }
    return *state == DutTcpState::kEstablished;
}

// Out-of-band (urgent) TCP receive — an opcode-only sub-interface. The standard
// AUTOSAR testability protocol exposes no urgent/OOB receive primitive (its
// RECEIVE_AND_FORWARD carries no urgent flag, and the spec has no MSG_OOB
// surface), so a backend that cannot answer returns nullptr from
// IDutControl::tcpRecvOob() and a case declaring kCapTcpRecvOob is
// capability-skipped on it (Tier 2 2b#4) rather than failed — the honest
// expression of the standard's limit, exactly like ITcpStateProbe.
class ITcpRecvOob {
public:
    virtual ~ITcpRecvOob() = default;

    // Receive up to `max_len` bytes from the socket's out-of-band (urgent) queue
    // (recv(MSG_OOB)). The urgent data must already have been delivered, so this
    // is a pure query — no trigger, unlike ITcpControl::receiveTcp's armed
    // receive. Returns the urgent bytes the DUT surfaced (1 per URG segment under
    // default sysctl), a refusal when the Upper Tester answered the receive
    // failed, or no answer.
    virtual DutReceiveOutcome receiveTcpOob(DutSocket sock, std::uint16_t max_len) = 0;
};

// AUTOSAR Testability backend of ITcpControl — thin adapter over the typed free
// functions in testability_client.h (the SP-encoding SSOT).
class TestabilityTcpControl final : public ITcpControl {
public:
    TestabilityTcpControl(const testability::TestabilityConfig &cfg, int timeout_ms,
                          std::uint32_t src_ip_be)
        : cfg_(cfg), timeout_ms_(timeout_ms), src_ip_be_(src_ip_be) {}

    std::optional<DutConnection> connectTcp(const Endpoint &peer,
                                            const BindSpec &local) override {
        const auto id = testability::testabilityCreateAndBind(
            cfg_, testability::kGidTcp, local.do_bind, local.local_port, local.local_addr_be,
            timeout_ms_, src_ip_be_);
        if (!id) {
            return std::nullopt;
        }
        if (!testability::testabilityTcpConnect(cfg_, *id, peer.port, peer.addr_be, timeout_ms_,
                                             src_ip_be_)
                 .eok()) {
            return std::nullopt;
        }
        return DutConnection{DutSocket{*id}, peer};
    }

    std::optional<DutConnection> acceptTcp(const BindSpec &listen,
                                           const std::function<void()> &trigger) override {
        const auto listen_id = testability::testabilityCreateAndBind(
            cfg_, testability::kGidTcp, listen.do_bind, listen.local_port, listen.local_addr_be,
            timeout_ms_, src_ip_be_);
        if (!listen_id) {
            return std::nullopt;
        }
        const auto ev = testability::testabilityTcpListenAndAccept(
            cfg_, *listen_id, static_cast<std::uint16_t>(::tc8::kDutPassiveListenBacklog), trigger,
            timeout_ms_, /*event_timeout_ms=*/2000, src_ip_be_);
        // The listen socket has done its job; the accepted connection lives on.
        testability::testabilityCloseSocket(cfg_, testability::kGidTcp, *listen_id, timeout_ms_,
                                         src_ip_be_);
        if (!ev.received) {
            return std::nullopt;
        }
        return DutConnection{DutSocket{ev.new_socket_id},
                             Endpoint{ev.client_addr_be, ev.client_port}};
    }

    std::optional<DutSocket> listenTcp(const BindSpec &listen) override {
        const auto listen_id = testability::testabilityCreateAndBind(
            cfg_, testability::kGidTcp, listen.do_bind, listen.local_port, listen.local_addr_be,
            timeout_ms_, src_ip_be_);
        if (!listen_id) {
            return std::nullopt;
        }
        // LISTEN_AND_ACCEPT, listen-only: the synchronous E_OK leaves the DUT in
        // LISTEN; the async accept Event is intentionally not awaited. The backlog
        // is the harness-wide one the opcode listen passes too
        // (tc8/dut_listen_backlog.h): a case that offers several connections at
        // once, such as TCP_CONNECTION_ESTAB_01's three SYNs, loses all but the
        // first on a stack that enforces the backlog exactly. The server's
        // accept thread also drains the accept queue, so a listen-only case whose
        // injected stimulus completes a handshake (e.g. FLAGS_PROCESSING_05's
        // SYN+ACK third-leg) does not back the queue up and block later SYNs; the
        // thread's lifetime is bounded by the socket (server stopWorker on close).
        if (!testability::testabilityTcpListen(
                 cfg_, *listen_id, static_cast<std::uint16_t>(::tc8::kDutPassiveListenBacklog),
                 timeout_ms_, src_ip_be_)
                 .eok()) {
            return std::nullopt;
        }
        return DutSocket{*listen_id};
    }

    std::optional<DutSocket> createTcp(const BindSpec &local) override {
        const auto id = testability::testabilityCreateAndBind(
            cfg_, testability::kGidTcp, local.do_bind, local.local_port, local.local_addr_be,
            timeout_ms_, src_ip_be_);
        if (!id) {
            return std::nullopt;
        }
        return DutSocket{*id};
    }

    bool sendTcp(DutSocket sock, const std::vector<std::uint8_t> &data) override {
        // SEND_DATA with totalLen == size: a literal send, no repeat.
        return testability::testabilityTcpSendData(cfg_, sock.id,
                                                static_cast<std::uint16_t>(data.size()),
                                                /*flags=*/0, data, timeout_ms_, src_ip_be_)
            .eok();
    }

    bool sendTcpWithFlags(DutSocket sock, const std::vector<std::uint8_t> &data,
                          TcpSendFlags flags) override {
        const std::uint8_t bits =
            static_cast<std::uint8_t>((flags.push ? testability::kSendFlagPsh : 0U) |
                                      (flags.urgent ? testability::kSendFlagUrg : 0U));
        return testability::testabilityTcpSendData(cfg_, sock.id,
                                                static_cast<std::uint16_t>(data.size()), bits,
                                                data, timeout_ms_, src_ip_be_)
            .eok();
    }

    bool sendTcpPattern(DutSocket sock, std::uint8_t pattern,
                        std::uint16_t total_len) override {
        // SEND_DATA: a one-byte template repeated to total_len (PRS_TPSP §6.10
        // totalLen rule) — the DUT generates the bytes, so a multi-kB fill
        // rides a tiny request.
        return testability::testabilityTcpSendData(cfg_, sock.id, total_len, /*flags=*/0,
                                                std::vector<std::uint8_t>{pattern},
                                                timeout_ms_, src_ip_be_)
            .eok();
    }

    DutReceiveOutcome receiveTcp(DutSocket sock, std::uint16_t max_len,
                                 const std::function<void()> &trigger) override {
        // Arm RECEIVE_AND_FORWARD (maxFwd = maxLen, so one Event carries the whole
        // bulk), drive the inbound data via trigger, collect the forwarded
        // payload. An arm that got no Response is no answer; one refused (a RID
        // other than E_OK) is the DUT's answer.
        const auto res = testability::testabilityReceiveAndForward(
            cfg_, sock.id, max_len, max_len, trigger, timeout_ms_, /*event_timeout_ms=*/2000,
            src_ip_be_);
        if (!res.responded) {
            return DutReceiveOutcome::noAnswer();
        }
        if (!res.ok) {
            return DutReceiveOutcome::refused();
        }
        return DutReceiveOutcome::received(res.payload);
    }

    bool shutdownTcpWr(DutSocket sock) override {
        // SHUTDOWN typeId=0x01 (further transmission disallowed) — graceful FIN,
        // read direction left open (PRS_TPSP §6.10).
        return testability::testabilityShutdown(cfg_, testability::kGidTcp, sock.id,
                                             testability::kShutdownWr, timeout_ms_, src_ip_be_)
            .eok();
    }

    DutCallOutcome closeTcp(DutSocket sock) override {
        return outcomeOf(testability::testabilityCloseSocket(cfg_, testability::kGidTcp, sock.id,
                                                             timeout_ms_, src_ip_be_));
    }

    DutCallOutcome abortTcp(DutSocket sock) override {
        // CLOSE_SOCKET with abort=true: immediate RST close, no wait for
        // outstanding tx/acks (PRS_TPSP §6.10 CLOSE_SOCKET abort param).
        return outcomeOf(testability::testabilityAbortSocket(cfg_, testability::kGidTcp, sock.id,
                                                             timeout_ms_, src_ip_be_));
    }

private:
    // PRS_TPSP §6.8: a response that never came is no answer; E_OK is done.
    // CLOSE_SOCKET lists E_TCP_CNE ("connection does not exist") for the RFC 793
    // 3.9 case, and E_ISD (invalid socket id) is what a server answers for an id it
    // no longer holds; both say the connection does not exist.
    static DutCallOutcome outcomeOf(const testability::TestabilityResponse &r) {
        if (!r.ok) {
            return DutCallOutcome::noAnswer();
        }
        if (r.rid == testability::kRidEOk) {
            return DutCallOutcome::done();
        }
        const bool no_connection =
            r.rid == testability::kRidETcpCne || r.rid == testability::kRidEIsd;
        return DutCallOutcome::refused(no_connection
                                           ? DutCallOutcome::Refusal::kConnectionDoesNotExist
                                           : DutCallOutcome::Refusal::kOther);
    }

    testability::TestabilityConfig cfg_;
    int timeout_ms_;
    std::uint32_t src_ip_be_;
};

// AUTOSAR Testability backend of IUdpControl — a one-shot CREATE_AND_BIND (to
// src_port) + SEND_DATA + CLOSE_SOCKET, presenting the connectionless send the
// seam asks for over the connection-table SPs.
class TestabilityUdpControl final : public IUdpControl {
public:
    TestabilityUdpControl(const testability::TestabilityConfig &cfg, int timeout_ms,
                          std::uint32_t src_ip_be)
        : cfg_(cfg), timeout_ms_(timeout_ms), src_ip_be_(src_ip_be) {}

    // Not available: CREATE_AND_BIND's response carries the socket id SEND_DATA
    // needs, so there is no sending without a reply.
    bool sendDatagramUnacknowledged(const Endpoint & /*src*/, const Endpoint & /*dest*/,
                                    const std::vector<std::uint8_t> & /*data*/) override {
        return false;
    }

    bool sendDatagram(const Endpoint &src, const Endpoint &dest,
                      const std::vector<std::uint8_t> &data) override {
        // `src.addr_be` IS the bind address: 0 keeps INADDR_ANY (the DUT's own
        // choice of egress address), non-zero pins the source the case asked for.
        const auto id = testability::testabilityCreateAndBind(cfg_, testability::kGidUdp,
                                                           /*do_bind=*/true, src.port,
                                                           src.addr_be,
                                                           timeout_ms_, src_ip_be_);
        if (!id) {
            return false;
        }
        const bool ok = testability::testabilityUdpSendData(
                            cfg_, *id, static_cast<std::uint16_t>(data.size()), dest.port,
                            dest.addr_be, data, timeout_ms_, src_ip_be_)
                            .eok();
        testability::testabilityCloseSocket(cfg_, testability::kGidUdp, *id, timeout_ms_,
                                         src_ip_be_);
        return ok;
    }

private:
    testability::TestabilityConfig cfg_;
    int timeout_ms_;
    std::uint32_t src_ip_be_;
};

// AUTOSAR Testability backend of IUdpReceiveControl: CREATE_AND_BIND the endpoint
// under test, arm RECEIVE_AND_FORWARD on it (PRS_TPSP §6.10), run the probe and
// then the sentinel, and collect the forwarded datagrams. The arm is made BEFORE
// the probe runs, which is why the verb is arm-then-trigger: an Event can only be
// forwarded for a datagram that arrives after the arm.
//
// What it reports is what the DUT forwarded, so an empty list alone is a silence
// (a dead forward loop forwards nothing either). The sentinel is what makes it an
// observation: it is well formed, sent to the same bound endpoint after the probe,
// and a DUT whose forward loop works delivers it. `path_proven` is true when it was
// delivered, or when the probe itself was (a delivered datagram proves the path).
class TestabilityUdpReceiveControl final : public IUdpReceiveControl {
public:
    TestabilityUdpReceiveControl(const testability::TestabilityConfig &cfg, int timeout_ms,
                                 std::uint32_t src_ip_be)
        : cfg_(cfg), timeout_ms_(timeout_ms), src_ip_be_(src_ip_be) {}

    std::optional<std::uint8_t> createReceivePorts(std::uint8_t count) override {
        // `count` sockets bound at once, then released: capacity is proven by holding
        // them together, not by creating one at a time.
        std::vector<std::uint16_t> held;
        for (std::uint8_t i = 0; i < count; ++i) {
            const auto id = testability::testabilityCreateAndBind(
                cfg_, testability::kGidUdp, /*do_bind=*/true, /*local_port=*/0xFFFF,
                /*local_addr_be=*/0, timeout_ms_, src_ip_be_);
            if (!id) {
                break;
            }
            held.push_back(*id);
        }
        for (const std::uint16_t id : held) {
            testability::testabilityCloseSocket(cfg_, testability::kGidUdp, id, timeout_ms_,
                                                src_ip_be_);
        }
        // Not even the first socket: the client cannot tell a refusal from no
        // answer, so this is not a count the DUT gave and is not graded as one.
        if (held.empty() && count != 0) {
            return std::nullopt;
        }
        return static_cast<std::uint8_t>(held.size());
    }

    DutUdpReceiveOutcome receiveUdp(const Endpoint &listen, const std::function<void()> &probe,
                                    const std::function<void()> &sentinel) override {
        // Bound on any address (see IUdpReceiveControl::receiveUdp): the port is the
        // scope, and the sentinel is what proves the path whatever the probe's
        // destination address was.
        const auto id = testability::testabilityCreateAndBind(
            cfg_, testability::kGidUdp, /*do_bind=*/true, listen.port, /*local_addr_be=*/0,
            timeout_ms_, src_ip_be_);
        if (!id) {
            return DutUdpReceiveOutcome::noAnswer();
        }
        bool sentinel_seen = false;
        const auto got = testability::testabilityReceiveDatagrams(
            cfg_, *id, kMaxForward,
            [&] {
                if (probe) {
                    probe();
                }
                if (sentinel) {
                    sentinel();
                }
            },
            [&](const testability::TestabilityDatagram &d) {
                // The sentinel ends the window: it was sent after the probe, so a
                // probe that reached the socket has been delivered by now.
                sentinel_seen = isSentinel(d);
                return sentinel_seen;
            },
            timeout_ms_, kWindowMs, src_ip_be_);
        testability::testabilityCloseSocket(cfg_, testability::kGidUdp, *id, timeout_ms_,
                                            src_ip_be_);
        if (!got.responded) {
            return DutUdpReceiveOutcome::noAnswer();
        }
        if (!got.ok) {
            return DutUdpReceiveOutcome::refused();
        }
        std::vector<DutReceivedDatagram> delivered;
        for (const auto &d : got.datagrams) {
            if (isSentinel(d)) {
                continue;
            }
            delivered.push_back(DutReceivedDatagram{Endpoint{d.src_addr_be, d.src_port},
                                                    d.full_len, d.payload});
        }
        const bool path_proven = sentinel_seen || !delivered.empty();
        return DutUdpReceiveOutcome::observed(std::move(delivered), path_proven);
    }

private:
    // Forwarded-payload cap of the arm: the most a datagram's bytes the Event
    // carries. A datagram longer than this still reports its true `full_len`.
    static constexpr std::uint16_t kMaxForward = 2048;
    // How long the window waits for the sentinel, and so for the probe ahead of it.
    static constexpr int kWindowMs = 2000;

    static bool isSentinel(const testability::TestabilityDatagram &d) {
        return d.payload.size() == kUdpReceiveSentinelPayload.size() &&
               std::equal(d.payload.begin(), d.payload.end(), kUdpReceiveSentinelPayload.begin());
    }

    testability::TestabilityConfig cfg_;
    int timeout_ms_;
    std::uint32_t src_ip_be_;
};

}  // namespace tc8::sce
