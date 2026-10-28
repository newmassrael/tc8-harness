#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

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
};

// The RECEIVE direction of the DUT's UDP data plane: open listening ports, and
// ask afterwards what arrived on one.
//
// A separate sub-interface rather than two more methods on IUdpControl, because
// a backend can provide one direction and not the other and the gate has to be
// able to say so. PRS_TPSP does define RECEIVE_AND_FORWARD, so a testability
// implementation is possible — but its "forward what you get" shape is not the
// same question as the opcode's "did you receive THIS, scoped to this
// destination", and mapping one onto the other on a guess would answer a
// different question than the case asked. Until that mapping is worked out from
// the spec, testability provides no implementation and the cases skip honestly.
class IUdpReceiveControl {
public:
    virtual ~IUdpReceiveControl() = default;

    // Have the DUT open `count` UDP receive ports. true on success.
    virtual bool createReceivePorts(std::uint8_t count) = 0;

    // Ask the DUT what it received on `listen.port`, scoped to datagrams whose
    // destination address was `listen.addr_be` (0 = any). The ANSWER reaches the
    // case through its own capture/verdict path, not through this return value —
    // true here means only that the DUT accepted the question.
    virtual bool queryReceived(const Endpoint &listen) = 0;
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

// Kernel-state probe — query the DUT's live socket state. This is the FIRST
// genuinely opcode-only sub-interface: no standard AUTOSAR testability service
// primitive exposes kernel TCP state (the standard surface is connection
// lifecycle + data, not introspection). A backend that cannot answer returns
// nullptr from IDutControl::tcpStateProbe(), and a case that declares
// kCapTcpStateProbe is capability-skipped on that backend rather than failed
// (Tier 2 2b#4) — the honest expression of the standard's limit. See
// docs/dut_control_seam.md.
class ITcpStateProbe {
public:
    virtual ~ITcpStateProbe() = default;

    // Has the DUT's socket reached ESTABLISHED? nullopt on query failure
    // (the case treats that as a third state, distinct from true/false).
    virtual std::optional<bool> isEstablished(DutSocket sock) = 0;

    // Live TCP_INFO snapshot of the DUT's socket, or nullopt on query failure.
    virtual std::optional<DutTcpInfo> queryInfo(DutSocket sock) = 0;
};

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
            cfg_, *listen_id, /*max_con=*/1, trigger, timeout_ms_, /*event_timeout_ms=*/2000,
            src_ip_be_);
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
        // LISTEN; the async accept Event is intentionally not awaited. max_con=1
        // for parity with acceptTcp and the opcode listen(fd, 1). The server's
        // accept thread also drains the accept queue, so a listen-only case whose
        // injected stimulus completes a handshake (e.g. FLAGS_PROCESSING_05's
        // SYN+ACK third-leg) does not back the queue up and block later SYNs; the
        // thread's lifetime is bounded by the socket (server stopWorker on close).
        if (!testability::testabilityTcpListen(cfg_, *listen_id, /*max_con=*/1, timeout_ms_,
                                            src_ip_be_)
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

}  // namespace tc8::sce
