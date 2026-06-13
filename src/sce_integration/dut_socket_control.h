#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <vector>

#include "stimulus/testability_client.h"
#include "tc8/testability_protocol.h"

namespace tc8::sce {

// Tier 2 socket-control seam (see claudedocs/testability_seam_tier2_design.md).
//
// The backend-agnostic vocabulary cases use to drive the DUT's socket data
// plane: open/send UDP, active/passive TCP open, send TCP, close. Each DUT
// control backend (opcode UT, AUTOSAR testability) implements this from its own
// transport — cases stay protocol-neutral. Operations whose wire shape only one
// backend supports (TCP kernel-state query, ARP conditioning, link-local) live
// on separate sub-interfaces, not here.
//
// Handles are opaque: a `DutSocket` is an id the backend issued; the seam does
// not encode the protocol group (the backend tracks it internally).

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

class ISocketControl {
public:
    virtual ~ISocketControl() = default;

    // CREATE_AND_BIND a UDP socket. nullopt on failure.
    virtual std::optional<DutSocket> openUdp(const BindSpec &spec) = 0;
    // SEND_DATA (UDP): transmit `data` (repeated up to total_len) to `dest`.
    virtual bool sendUdp(DutSocket sock, const Endpoint &dest,
                         const std::vector<std::uint8_t> &data, std::uint16_t total_len) = 0;

    // Active open: the DUT connects to `peer` (the caller's listener). Returns
    // the DUT's connected socket, or nullopt on failure.
    virtual std::optional<DutConnection> connectTcp(const Endpoint &peer) = 0;
    // Passive open: the DUT binds+listens per `listen`; `trigger` drives one
    // inbound connection once the DUT is listening; returns the accepted
    // connection (with the client endpoint), or nullopt if none arrived.
    virtual std::optional<DutConnection> acceptTcp(const BindSpec &listen,
                                                   const std::function<void()> &trigger) = 0;
    // SEND_DATA (TCP): transmit `data` (repeated up to total_len) on `conn`.
    virtual bool sendTcp(const DutConnection &conn, const std::vector<std::uint8_t> &data,
                         std::uint16_t total_len) = 0;

    // CLOSE_SOCKET the given DUT socket.
    virtual bool closeSocket(DutSocket sock) = 0;
};

// AUTOSAR Testability backend of ISocketControl — thin adapter over the typed
// free functions in testability_client.h (the SP-encoding SSOT). Tracks each
// socket's service group so CLOSE_SOCKET addresses the right group while the
// seam handle stays opaque.
class TestabilitySocketControl final : public ISocketControl {
public:
    TestabilitySocketControl(const stimulus::TestabilityConfig &cfg, int timeout_ms,
                             std::uint32_t src_ip_be)
        : cfg_(cfg), timeout_ms_(timeout_ms), src_ip_be_(src_ip_be) {}

    std::optional<DutSocket> openUdp(const BindSpec &spec) override {
        const auto id = stimulus::testabilityCreateAndBind(cfg_, testability::kGidUdp,
                                                           spec.do_bind, spec.local_port,
                                                           spec.local_addr_be, timeout_ms_,
                                                           src_ip_be_);
        if (!id) {
            return std::nullopt;
        }
        socket_gid_[*id] = testability::kGidUdp;
        return DutSocket{*id};
    }

    bool sendUdp(DutSocket sock, const Endpoint &dest,
                 const std::vector<std::uint8_t> &data, std::uint16_t total_len) override {
        return stimulus::testabilityUdpSendData(cfg_, sock.id, total_len, dest.port,
                                                dest.addr_be, data, timeout_ms_, src_ip_be_)
            .eok();
    }

    std::optional<DutConnection> connectTcp(const Endpoint &peer) override {
        const auto id = stimulus::testabilityCreateAndBind(cfg_, testability::kGidTcp,
                                                           /*do_bind=*/false, 0xFFFF, 0,
                                                           timeout_ms_, src_ip_be_);
        if (!id) {
            return std::nullopt;
        }
        socket_gid_[*id] = testability::kGidTcp;
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
        socket_gid_[*listen_id] = testability::kGidTcp;
        const auto ev = stimulus::testabilityTcpListenAndAccept(
            cfg_, *listen_id, /*max_con=*/1, trigger, timeout_ms_, /*event_timeout_ms=*/2000,
            src_ip_be_);
        if (!ev.received) {
            return std::nullopt;
        }
        socket_gid_[ev.new_socket_id] = testability::kGidTcp;
        return DutConnection{DutSocket{ev.new_socket_id},
                             Endpoint{ev.client_addr_be, ev.client_port}};
    }

    bool sendTcp(const DutConnection &conn, const std::vector<std::uint8_t> &data,
                 std::uint16_t total_len) override {
        return stimulus::testabilityTcpSendData(cfg_, conn.socket.id, total_len, /*flags=*/0,
                                                data, timeout_ms_, src_ip_be_)
            .eok();
    }

    bool closeSocket(DutSocket sock) override {
        const auto it = socket_gid_.find(sock.id);
        const std::uint8_t gid = (it != socket_gid_.end())
                                     ? it->second
                                     : static_cast<std::uint8_t>(testability::kGidTcp);
        const bool ok =
            stimulus::testabilityCloseSocket(cfg_, gid, sock.id, timeout_ms_, src_ip_be_).eok();
        if (it != socket_gid_.end()) {
            socket_gid_.erase(it);
        }
        return ok;
    }

private:
    stimulus::TestabilityConfig cfg_;
    int timeout_ms_;
    std::uint32_t src_ip_be_;
    std::map<std::uint16_t, std::uint8_t> socket_gid_;  // socketId -> service group
};

}  // namespace tc8::sce
