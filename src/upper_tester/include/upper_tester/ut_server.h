#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include "tc8/net/socket_backend.h"
#include "tc8/upper_tester_protocol.h"
#include "upper_tester/stack_probe.h"

namespace tc8::ut {

// TC8 §4.8.5 Upper Tester server, the platform-agnostic core. It owns the wire
// codec dispatch, every opcode's request parsing and response framing, the TCP
// session slot table + acceptor/connector worker lifecycle, the §4.4 ADDRESSING
// data listener (receipt store + RFC 1122 directed-broadcast / multicast
// silent-discard), and the dynamic UDP receive ports — all written once — and
// delegates each network operation to an injected net::SocketBackend (the socket
// primitives, shared with the testability server) plus an ut::StackProbe (the
// TCP-info / OOB / original-destination introspection). A Linux deployment pairs
// it with the POSIX adapters, the lwIP fixture with lwIP adapters; the wire
// framing is the shared SSOT in include/tc8/upper_tester_protocol.h.
//
// Opcode dispatch is a handler table (opcode -> handler), not a switch: the
// table is the single source for admission, the OpQueryCapabilities bitmap, and
// the OpPing contiguous-top — none can drift from the set the server actually
// serves. Platform-specific opcode families (the reference DUT's §4.5 and §4.7
// autoconf/DHCP 0x0C..0x12, an lwIP DUT's §4.2 ARP conditioning 0x17) are added
// with registerOpcode() rather than baked into the core.
//
// RAII: start() spawns the data + UT listener threads; stop()/dtor joins them,
// tears down any TCP sessions, and closes the dynamic receive ports.
class UpperTesterServer {
public:
    UpperTesterServer(std::unique_ptr<net::SocketBackend> backend,
                      std::unique_ptr<StackProbe> probe);
    ~UpperTesterServer();

    UpperTesterServer(const UpperTesterServer &) = delete;
    UpperTesterServer &operator=(const UpperTesterServer &) = delete;

    // A synchronous opcode handler: reads the request params (everything past
    // the 2-byte opcode/req_id header) and fills the response status + body.
    // Runs on the UT server thread, request/response only.
    using OpcodeHandler =
        std::function<void(const std::uint8_t *params, std::size_t len,
                           std::uint8_t &status, std::vector<std::uint8_t> &body)>;

    // Register a platform-specific opcode (e.g. autoconf/DHCP/ARP conditioning).
    // The opcode joins the admission set, the capability bitmap, and — if it
    // extends the contiguous 0x01.. block — the OpPing top. Call before start():
    // the table is read-only while the server thread runs. Overwrites a prior
    // registration for the same opcode (extension wins, mirroring the testability
    // registerPrimitive override seam).
    void registerOpcode(std::uint8_t opcode, OpcodeHandler handler);

    // Arm an app-layer reception fault on the data listener (the kAppFault* catalog
    // in upper_tester_protocol.h). While a non-None flavor is set, dataListenerLoop
    // skips the matching RFC 1122 destination-address discard so a buggy DUT counts a
    // datagram it must drop — the reception a §4.4.4.5 positive proves absent. The
    // destination-address discard is shared-core conformant behaviour, and a
    // post-delivery app decision is out of the fixture's netif-level reach, so the fault
    // STATE must live here; it is co-located with the policy it bypasses — a deliberate
    // choice over a separate discard-predicate seam, since the skip is a one-line gate.
    // The OpSetAppFlavor opcode that drives it is registered only by the lwIP fixture, so
    // the kernel-backed tc8-dut never arms it. Thread-safe: written from
    // the OpSetAppFlavor handler on the UT thread, read on the data-listener thread.
    void setAppFaultFlavor(std::uint8_t flavor);

    // Bind the data + UT listener sockets and start the server threads.
    // `iface_ip_be` is the source the OpTriggerSendUdp default binds to;
    // `iface_bcast_be` is the directed-broadcast the data listener silently
    // discards (§4.4.4.5 ADDRESSING_02) — 0 disables that discard. false if
    // either bind fails. No-op-safe to call once.
    bool start(std::uint32_t iface_ip_be, std::uint32_t iface_bcast_be,
               std::uint16_t ut_port = kPort, std::uint16_t data_port = kDataPort);

    // Signal the threads to exit, join them, tear down TCP sessions + receive
    // ports, and close the listener sockets. Idempotent. `abort` RSTs each live
    // connection (closeWithAbort) instead of a graceful close: a userspace-stack
    // DUT (lwIP) needs this on teardown so a case-leaked connection's tester-side
    // half reaches CLOSED rather than orphaning in FIN-WAIT-2 and swallowing the
    // next respawn's SYN on the reused port quad — a kernel DUT (Linux) instead
    // relies on the OS closing sockets on process death and tears down gracefully.
    void stop(bool abort = false);

private:
    enum class TcpKind : std::uint8_t { Passive = 0, Active = 1 };

    struct TcpSlot {
        TcpKind kind = TcpKind::Passive;
        int listen_fd = -1;     // passive only; -1 for active
        int accepted_fd = -1;   // populated by acceptor / connector
        std::uint16_t local_port = 0;
        std::uint32_t remote_ip_be = 0;  // active only
        std::uint16_t remote_port = 0;   // active only
        std::atomic<bool> stop{false};
        std::thread worker;  // acceptor (passive) / connector (active)
    };

    struct ReceiveRecord {
        std::uint32_t src_ip = 0;    // network byte order
        std::uint32_t dst_ip = 0;    // network byte order (original wire dst)
        std::uint16_t src_port = 0;
        std::uint16_t dst_port = 0;
        std::vector<std::uint8_t> payload;
        bool populated = false;
    };

    void installBuiltins();
    void utServerLoop();
    void dataListenerLoop();
    void dispatch(std::uint8_t opcode, const std::uint8_t *params, std::size_t len,
                  std::uint8_t &status, std::vector<std::uint8_t> &body);
    void sendResponse(const net::Endpoint &peer, std::uint8_t response_opcode,
                      std::uint8_t req_id, std::uint8_t status,
                      const std::vector<std::uint8_t> &body);

    // Built-in opcode handlers (one per common opcode the core serves).
    void handleGetReceivedUdp(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                              std::vector<std::uint8_t> &body);
    void handleTriggerSendUdp(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                              std::vector<std::uint8_t> &body);
    void handleOpenTcpSocket(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                             std::vector<std::uint8_t> &body);
    void handleCloseTcpSocket(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                              std::vector<std::uint8_t> &body);
    void handleQueryTcpEstablished(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                   std::vector<std::uint8_t> &body);
    void handleSendTcpData(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                           std::vector<std::uint8_t> &body);
    void handleReceiveTcpData(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                              std::vector<std::uint8_t> &body);
    void handleShutdownTcpSocketWr(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                   std::vector<std::uint8_t> &body);
    void handleAbortTcpSocket(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                              std::vector<std::uint8_t> &body);
    void handleSendTcpDataPattern(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                  std::vector<std::uint8_t> &body);
    void handleReceiveTcpDataOob(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                 std::vector<std::uint8_t> &body);
    void handleQueryTcpInfo(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                            std::vector<std::uint8_t> &body);
    void handleCreateUdpReceivePorts(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                     std::vector<std::uint8_t> &body);
    void handlePing(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                    std::vector<std::uint8_t> &body);
    void handleQueryCapabilities(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                 std::vector<std::uint8_t> &body);

    // TCP session backend (used by the handlers above).
    std::optional<std::uint8_t> openTcpPassive(std::uint16_t local_port);
    std::optional<std::uint8_t> openTcpActive(std::uint16_t local_port,
                                              std::uint32_t remote_ip_be,
                                              std::uint16_t remote_port);
    bool tearDownSlot(std::uint8_t socket_id, bool abort);
    bool slotExists(std::uint8_t socket_id) const;
    int slotConnFd(std::uint8_t socket_id) const;  // accepted_fd, or -1
    void tcpAcceptorLoop(TcpSlot *slot);
    void tcpConnectorLoop(TcpSlot *slot, std::uint32_t remote_ip_be, std::uint16_t remote_port);

    bool triggerSendUdp(std::uint16_t src_port, std::uint32_t dst_ip_be, std::uint16_t dst_port,
                        const std::uint8_t *payload, std::uint16_t payload_len,
                        std::uint32_t src_ip_override_be);
    std::uint8_t createUdpReceivePorts(std::uint8_t count);
    std::optional<ReceiveRecord> lookupReceipt(std::uint16_t listen_port,
                                               std::uint32_t expected_dst_ip_be);

    std::unique_ptr<net::SocketBackend> backend_;
    std::unique_ptr<StackProbe> probe_;

    std::map<std::uint8_t, OpcodeHandler> handlers_;  // dispatch SSOT (read-only after start)
    std::array<std::uint8_t, kCapabilityBitmapBytes> capability_bitmap_{};
    std::uint8_t ping_max_opcode_ = 0;

    std::uint32_t iface_ip_be_ = 0;
    std::uint32_t iface_bcast_be_ = 0;
    std::uint16_t data_port_ = 0;
    // App-layer reception-fault flavor (kAppFault*). Default None = the data listener
    // applies every RFC 1122 dst-address discard; armed lwIP-only via OpSetAppFlavor.
    std::atomic<std::uint8_t> app_fault_flavor_{kAppFaultNone};

    int data_fd_ = -1;
    int ut_fd_ = -1;
    std::thread data_thread_;
    std::thread ut_thread_;
    std::atomic<bool> stop_requested_{false};

    mutable std::mutex tcp_mu_;
    std::map<std::uint8_t, std::unique_ptr<TcpSlot>> tcp_slots_;
    std::uint8_t next_tcp_socket_id_ = 1;

    std::mutex log_mu_;
    ReceiveRecord last_receipt_{};

    std::mutex udp_receive_ports_mu_;
    std::vector<int> udp_receive_ports_;
};

}  // namespace tc8::ut
