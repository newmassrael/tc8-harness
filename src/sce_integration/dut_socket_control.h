#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "stimulus/testability_client.h"
#include "tc8/testability_protocol.h"

namespace tc8::sce {

// Tier 2 data-plane seam (see claudedocs/testability_seam_tier2_design.md).
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
    // Receive up to `max_len` bytes the DUT has on `sock`. `trigger` drives the
    // inbound data (e.g. inject a tester segment): the testability backend ARMS
    // RECEIVE_AND_FORWARD before invoking trigger so the forwarded bytes are
    // captured, while the opcode backend invokes trigger then queries
    // OpReceiveTcpData (its kernel already queued the bytes). Returns the bytes
    // the DUT received (<= max_len); nullopt when the seam call itself failed
    // (arm / round-trip error or no Event within the timeout), and an empty
    // vector when the DUT genuinely received zero bytes — the same nullopt
    // failure model and at-most-once `trigger` call-count contract as acceptTcp,
    // which the arm-then-trigger control flow mirrors.
    virtual std::optional<std::vector<std::uint8_t>> receiveTcp(
        DutSocket sock, std::uint16_t max_len, const std::function<void()> &trigger) = 0;
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
    virtual bool closeTcp(DutSocket sock) = 0;
    // Abortive close: the DUT closes the socket immediately with a RST (no
    // graceful FIN), not waiting for outstanding transmissions/acknowledgements —
    // the application ABORT primitive (RFC 793 §3.9). opcode OpAbortTcpSocket
    // (SO_LINGER {1,0} + close), testability CLOSE_SOCKET with the abort flag set
    // (PRS_TPSP §6.10 CLOSE_SOCKET abort param). Split from closeTcp's graceful
    // ::close so each verb is a total function both backends implement faithfully.
    virtual bool abortTcp(DutSocket sock) = 0;
};

// One-shot UDP send — no handle, matching the opcode UT's port-based model.
class IUdpControl {
public:
    virtual ~IUdpControl() = default;

    // Make the DUT emit one UDP datagram from `src_port` to `dest` carrying
    // `data`. true on success.
    virtual bool sendDatagram(std::uint16_t src_port, const Endpoint &dest,
                              const std::vector<std::uint8_t> &data) = 0;
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
// claudedocs/testability_seam_tier2_design.md.
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
    // default sysctl), or nullopt on query failure.
    virtual std::optional<std::vector<std::uint8_t>> receiveTcpOob(DutSocket sock,
                                                                   std::uint16_t max_len) = 0;
};

// AUTOSAR Testability backend of ITcpControl — thin adapter over the typed free
// functions in testability_client.h (the SP-encoding SSOT).
class TestabilityTcpControl final : public ITcpControl {
public:
    TestabilityTcpControl(const stimulus::TestabilityConfig &cfg, int timeout_ms,
                          std::uint32_t src_ip_be)
        : cfg_(cfg), timeout_ms_(timeout_ms), src_ip_be_(src_ip_be) {}

    std::optional<DutConnection> connectTcp(const Endpoint &peer,
                                            const BindSpec &local) override {
        const auto id = stimulus::testabilityCreateAndBind(
            cfg_, testability::kGidTcp, local.do_bind, local.local_port, local.local_addr_be,
            timeout_ms_, src_ip_be_);
        if (!id) {
            return std::nullopt;
        }
        if (!stimulus::testabilityTcpConnect(cfg_, *id, peer.port, peer.addr_be, timeout_ms_,
                                             src_ip_be_)
                 .eok()) {
            return std::nullopt;
        }
        return DutConnection{DutSocket{*id}, peer};
    }

    std::optional<DutConnection> acceptTcp(const BindSpec &listen,
                                           const std::function<void()> &trigger) override {
        const auto listen_id = stimulus::testabilityCreateAndBind(
            cfg_, testability::kGidTcp, listen.do_bind, listen.local_port, listen.local_addr_be,
            timeout_ms_, src_ip_be_);
        if (!listen_id) {
            return std::nullopt;
        }
        const auto ev = stimulus::testabilityTcpListenAndAccept(
            cfg_, *listen_id, /*max_con=*/1, trigger, timeout_ms_, /*event_timeout_ms=*/2000,
            src_ip_be_);
        // The listen socket has done its job; the accepted connection lives on.
        stimulus::testabilityCloseSocket(cfg_, testability::kGidTcp, *listen_id, timeout_ms_,
                                         src_ip_be_);
        if (!ev.received) {
            return std::nullopt;
        }
        return DutConnection{DutSocket{ev.new_socket_id},
                             Endpoint{ev.client_addr_be, ev.client_port}};
    }

    std::optional<DutSocket> listenTcp(const BindSpec &listen) override {
        const auto listen_id = stimulus::testabilityCreateAndBind(
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
        if (!stimulus::testabilityTcpListen(cfg_, *listen_id, /*max_con=*/1, timeout_ms_,
                                            src_ip_be_)
                 .eok()) {
            return std::nullopt;
        }
        return DutSocket{*listen_id};
    }

    bool sendTcp(DutSocket sock, const std::vector<std::uint8_t> &data) override {
        // SEND_DATA with totalLen == size: a literal send, no repeat.
        return stimulus::testabilityTcpSendData(cfg_, sock.id,
                                                static_cast<std::uint16_t>(data.size()),
                                                /*flags=*/0, data, timeout_ms_, src_ip_be_)
            .eok();
    }

    bool sendTcpPattern(DutSocket sock, std::uint8_t pattern,
                        std::uint16_t total_len) override {
        // SEND_DATA: a one-byte template repeated to total_len (PRS_TPSP §6.10
        // totalLen rule) — the DUT generates the bytes, so a multi-kB fill
        // rides a tiny request.
        return stimulus::testabilityTcpSendData(cfg_, sock.id, total_len, /*flags=*/0,
                                                std::vector<std::uint8_t>{pattern},
                                                timeout_ms_, src_ip_be_)
            .eok();
    }

    std::optional<std::vector<std::uint8_t>> receiveTcp(
        DutSocket sock, std::uint16_t max_len,
        const std::function<void()> &trigger) override {
        // Arm RECEIVE_AND_FORWARD (maxFwd = maxLen, so one Event carries the whole
        // bulk), drive the inbound data via trigger, collect the forwarded
        // payload. nullopt only when the arm itself failed to round-trip.
        const auto res = stimulus::testabilityReceiveAndForward(
            cfg_, sock.id, max_len, max_len, trigger, timeout_ms_, /*event_timeout_ms=*/2000,
            src_ip_be_);
        if (!res.ok) {
            return std::nullopt;
        }
        return res.payload;
    }

    bool shutdownTcpWr(DutSocket sock) override {
        // SHUTDOWN typeId=0x01 (further transmission disallowed) — graceful FIN,
        // read direction left open (PRS_TPSP §6.10).
        return stimulus::testabilityShutdown(cfg_, testability::kGidTcp, sock.id,
                                             testability::kShutdownWr, timeout_ms_, src_ip_be_)
            .eok();
    }

    bool closeTcp(DutSocket sock) override {
        return stimulus::testabilityCloseSocket(cfg_, testability::kGidTcp, sock.id, timeout_ms_,
                                                src_ip_be_)
            .eok();
    }

    bool abortTcp(DutSocket sock) override {
        // CLOSE_SOCKET with abort=true: immediate RST close, no wait for
        // outstanding tx/acks (PRS_TPSP §6.10 CLOSE_SOCKET abort param).
        return stimulus::testabilityAbortSocket(cfg_, testability::kGidTcp, sock.id, timeout_ms_,
                                                src_ip_be_)
            .eok();
    }

private:
    stimulus::TestabilityConfig cfg_;
    int timeout_ms_;
    std::uint32_t src_ip_be_;
};

// AUTOSAR Testability backend of IUdpControl — a one-shot CREATE_AND_BIND (to
// src_port) + SEND_DATA + CLOSE_SOCKET, presenting the connectionless send the
// seam asks for over the connection-table SPs.
class TestabilityUdpControl final : public IUdpControl {
public:
    TestabilityUdpControl(const stimulus::TestabilityConfig &cfg, int timeout_ms,
                          std::uint32_t src_ip_be)
        : cfg_(cfg), timeout_ms_(timeout_ms), src_ip_be_(src_ip_be) {}

    bool sendDatagram(std::uint16_t src_port, const Endpoint &dest,
                      const std::vector<std::uint8_t> &data) override {
        const auto id = stimulus::testabilityCreateAndBind(cfg_, testability::kGidUdp,
                                                           /*do_bind=*/true, src_port, 0,
                                                           timeout_ms_, src_ip_be_);
        if (!id) {
            return false;
        }
        const bool ok = stimulus::testabilityUdpSendData(
                            cfg_, *id, static_cast<std::uint16_t>(data.size()), dest.port,
                            dest.addr_be, data, timeout_ms_, src_ip_be_)
                            .eok();
        stimulus::testabilityCloseSocket(cfg_, testability::kGidUdp, *id, timeout_ms_,
                                         src_ip_be_);
        return ok;
    }

private:
    stimulus::TestabilityConfig cfg_;
    int timeout_ms_;
    std::uint32_t src_ip_be_;
};

}  // namespace tc8::sce
