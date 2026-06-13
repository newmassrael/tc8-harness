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
    virtual std::optional<DutConnection> acceptTcp(const BindSpec &listen,
                                                   const std::function<void()> &trigger) = 0;
    // Transmit `data` (repeated up to total_len) on the connected socket.
    virtual bool sendTcp(DutSocket sock, const std::vector<std::uint8_t> &data,
                         std::uint16_t total_len) = 0;
    // Close a TCP socket.
    virtual bool closeTcp(DutSocket sock) = 0;
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

    bool sendTcp(DutSocket sock, const std::vector<std::uint8_t> &data,
                 std::uint16_t total_len) override {
        return stimulus::testabilityTcpSendData(cfg_, sock.id, total_len, /*flags=*/0, data,
                                                timeout_ms_, src_ip_be_)
            .eok();
    }

    bool closeTcp(DutSocket sock) override {
        return stimulus::testabilityCloseSocket(cfg_, testability::kGidTcp, sock.id, timeout_ms_,
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
