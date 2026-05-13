#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>

#include "dhcpv4_client.h"
#include "linklocal_autoconf.h"

namespace tc8::dut {

// TC8 §4.8.5 Upper Tester implementation, tc8-dut side.
//
// Spawns two daemon threads while alive:
//
//   * Data listener — binds UDP INADDR_ANY on the spec-named
//     `unusedUDPSrcPort` (20000), enables IP_PKTINFO so receive events
//     carry the original IP destination. Records the last receipt per
//     (port, dst_ip) tuple in a bounded log the UT server then
//     queries. Events whose dst_ip matches the iface directed-
//     broadcast (e.g. 172.16.0.255 for 172.16.0.2/24) are silently
//     DROPPED — this is the §4.4.4.5 IPv4_ADDRESSING_02 conformance
//     behaviour, baked into the application layer per RFC 1122
//     RFC 1122 §3.2.1.3 "SHOULD silently discard."
//
//   * UT RPC server — binds UDP INADDR_ANY on `ut::kPort` (30600),
//     parses requests per `tc8/upper_tester_protocol.h`, and emits
//     Confirmation responses. `OpGetReceivedUdp` consults the data
//     listener's log; `OpTriggerSendUdp` opens a transient socket,
//     binds to the iface IP + requested src_port, and sendto()s.
//
// Both threads loop on blocking `recvmsg` with SO_RCVTIMEO=200 ms so
// `stop()` can shut them down inside a single poll tick. Lifetime is
// RAII — construction starts threads, destruction joins them.
class UpperTesterServer {
public:
    UpperTesterServer();
    ~UpperTesterServer();

    UpperTesterServer(const UpperTesterServer&)            = delete;
    UpperTesterServer& operator=(const UpperTesterServer&) = delete;

    // Start both listener threads. Returns false if either socket
    // fails to bind — caller should abort startup in that case (no
    // UT = every §4.4.4.5 / §4.4.4.6 case will fail on timeout, which is a
    // clearer failure mode than silent running without UT).
    bool start();

    // Signal both threads to exit and join them. Idempotent.
    void stop();

private:
    struct ReceiveRecord {
        std::uint32_t src_ip   = 0;     // NBO
        std::uint32_t dst_ip   = 0;     // NBO (original wire destination)
        std::uint16_t src_port = 0;
        std::uint16_t dst_port = 0;
        std::vector<std::uint8_t> payload;
        bool          populated = false;
    };

    void dataListenerLoop(int fd);
    void utServerLoop(int fd);
    void sendResponse(int fd, const sockaddr_storage &peer, socklen_t peer_len,
                      std::uint8_t opcode, std::uint8_t req_id,
                      std::uint8_t status,
                      const std::vector<std::uint8_t> &body);
    bool triggerSendUdp(std::uint16_t src_port, std::uint32_t dst_ip_be,
                        std::uint16_t dst_port, const std::uint8_t *payload,
                        std::uint16_t payload_len,
                        std::uint32_t src_ip_override_be);

    std::optional<ReceiveRecord> lookupReceipt(std::uint16_t listen_port,
                                                std::uint32_t expected_dst_ip_be);

    std::uint32_t ifaceIpBe() const { return iface_ip_be_; }

    // §4.8.5 TCP procedure backend. One TcpListener per
    // OpOpenTcpSocket call. Two flavours, selected by the request's
    // leading `type` byte:
    //
    //   * Passive: socket+bind+listen on `listen_fd`, then a one-shot
    //     acceptor thread polls `listen_fd` until accept() yields the
    //     connected socket. `accepted_fd` is the connected socket; the
    //     listen socket is preserved on `listen_fd` until close.
    //   * Active: socket+bind to (iface_ip, local_port)+connect to the
    //     caller-supplied remote endpoint, on a worker thread so the UT
    //     RPC reply does not block on the SYN→SYN+ACK round-trip. The
    //     same connected fd is stored on `accepted_fd`; `listen_fd`
    //     stays -1 because no listener participates.
    //
    // OpQueryTcpEstablished reads `accepted_fd`'s actual TCP state via
    // `getsockopt(SOL_TCP, TCP_INFO)` and returns 1 iff `tcpi_state ==
    // TCP_ESTABLISHED`, working uniformly for both flavours. No
    // surrogate flag — the kernel's view of the connection state is the
    // only source of truth so a future case observing a non-ESTABLISHED
    // state (SYN-SENT, FIN-WAIT-1, etc.) can extend `queryTcpState`
    // without adding a parallel atomic per state.
    enum class TcpListenerKind : std::uint8_t {
        Passive = 0,
        Active  = 1,
    };

    struct TcpListener {
        TcpListenerKind kind         = TcpListenerKind::Passive;
        int             listen_fd    = -1;        // passive only; -1 for active
        int             accepted_fd  = -1;        // populated by acceptor / connector
        std::uint16_t   local_port   = 0;
        // Active-socket endpoint identity. Populated at OpenTcpActive
        // time so abortTcpSocket can issue a 4-tuple-targeted
        // sock_diag SOCK_DESTROY for sockets in TIME-WAIT — Linux's
        // TW state lives in tw_sock, separate from the regular sk
        // close path; SO_LINGER {1,0} + close() does NOT terminate
        // a TW socket. Passive sockets leave both fields zero
        // (the accepted-side 4-tuple would need getpeername off the
        // accepted_fd; deferred until a passive consumer needs it).
        std::uint32_t   remote_ip_be = 0;
        std::uint16_t   remote_port  = 0;
        std::atomic<bool> stop{false};
        std::thread     worker;                   // acceptor (passive) / connector (active)
    };

    // §4.8.6.11 TCP_RETRANSMISSION_TO kernel-side snapshot exposed by
    // `OpQueryTcpInfo` (0x13). Mirrors the four `struct tcp_info` fields
    // the §4.8.6.11 cluster verdicts on without depending on pcap timing
    // of retransmits — see `tc8::ut::OpQueryTcpInfo` documentation in
    // `include/tc8/upper_tester_protocol.h`.
    struct TcpInfoSnapshot {
        std::uint8_t  state       = 0;  // tcpi_state (1=ESTABLISHED, ...)
        std::uint32_t rto_us      = 0;  // tcpi_rto in microseconds
        std::uint8_t  retransmits = 0;  // tcpi_retransmits (icsk_retransmits)
        std::uint32_t unacked     = 0;  // tcpi_unacked (tp->packets_out)
    };

    // Mutates `tcp_listeners_` and `next_tcp_socket_id_`.
    std::optional<std::uint8_t> openTcpPassive(std::uint16_t local_port);
    std::optional<std::uint8_t> openTcpActive(std::uint16_t local_port,
                                              std::uint32_t remote_ip_be,
                                              std::uint16_t remote_port);
    bool                         closeTcpSocket(std::uint8_t socket_id);
    std::optional<bool>          queryTcpEstablished(std::uint8_t socket_id);
    std::optional<TcpInfoSnapshot> queryTcpInfo(std::uint8_t socket_id);

    // §4.8.6.2 CHECKSUM_03 backend: write `payload_len` bytes to the
    // socket's connected fd via `::send()` and let Linux's TCP stack
    // frame the data into outbound segments. Returns false on any
    // syscall failure (unknown socket_id collapses to ENOTCONN-class
    // failure on the surface). Partial writes are retried within the
    // call so a UT response carries the truthful "all bytes accepted /
    // none accepted" verdict — TCP_CHECKSUM_03 verifies the DUT-emitted
    // segment in pcap, not the byte count, so a multi-segment write is
    // benign for the spec assertion.
    bool sendTcpData(std::uint8_t        socket_id,
                     const std::uint8_t *payload,
                     std::uint16_t       payload_len);

    // §4.8.6.9 MSS_OPTIONS_06/_09/_10 backend: allocate `total_len`
    // bytes filled with `pattern` and write them via ::send(). Lets
    // the harness drive 1500+ B writes without ballooning the UT
    // request datagram past MTU — the bulk-data generation lives
    // server-side; the wire request stays compact (6 bytes).
    bool sendTcpDataPattern(std::uint8_t  socket_id,
                            std::uint8_t  pattern,
                            std::uint16_t total_len);

    // §4.8.6.8 TCP_CLOSING_07/_08 backend: drain up to `expected_len`
    // bytes from the connected fd associated with `socket_id`, blocking
    // up to `timeout_ms` total. Returns the bytes actually read; an
    // empty return implies "timeout with no data" or "unknown socket"
    // (the dispatch case-out in `utServerLoop` distinguishes those by
    // checking the socket map first). The recv loop coalesces partial
    // reads — Linux can return less than the request on a short-burst
    // arrival — into one buffer up to expected_len.
    std::vector<std::uint8_t> receiveTcpData(std::uint8_t  socket_id,
                                             std::uint16_t expected_len,
                                             std::uint16_t timeout_ms);

    // §4.8.6.14 TCP_URGENT_PTR_04 backend: drain up to `expected_len`
    // bytes from the OOB queue of the connected fd via
    // ::recv(MSG_OOB), blocking up to `timeout_ms`. Linux's default
    // socket options (SO_OOBINLINE off, sysctl_tcp_stdurg=0) place
    // exactly one byte at urg_seq in the OOB queue per URG segment;
    // a successful call returns one urgent byte. Returns the bytes
    // actually read; an empty return implies "timeout / no urgent
    // data" or "unknown socket".
    std::vector<std::uint8_t> receiveTcpDataOob(std::uint8_t  socket_id,
                                                std::uint16_t expected_len,
                                                std::uint16_t timeout_ms);

    // §4.8.6.8 TCP_CLOSING_07/_08 backend: shutdown(SHUT_WR) the
    // socket's connected fd. Kernel emits FIN; read direction stays
    // open so a subsequent receiveTcpData can drain bytes that
    // arrived in FW1/FW2. Returns false if the socket is unknown or
    // shutdown() fails.
    bool shutdownTcpSocketWr(std::uint8_t socket_id);

    // §4.8.6.5 TCP_CALL_ABORT_02/_03 backend: apply SO_LINGER
    // {l_onoff=1, l_linger=0} to the socket's connected fd, then
    // ::close() the listener. Linux emits RST instead of FIN per
    // socket(7) LINGER semantics and disposes the socket without
    // entering FW1/FW2/TIME-WAIT. The TcpListener is then erased
    // from `tcp_listeners_` so subsequent OpQueryTcpEstablished /
    // OpReceiveTcpData on the same id return kStatusUnknownSocket
    // (matching the semantics of OpCloseTcpSocket post-close).
    // Returns false if the socket is unknown.
    bool abortTcpSocket(std::uint8_t socket_id);

    // Acceptor thread body (passive). Polls listen_fd with 200 ms
    // timeout, calls accept on POLLIN, stops on `listener->stop` or
    // accept success. Single-shot — BASICS only need one connected
    // client per listener.
    void tcpAcceptorLoop(TcpListener *listener);

    // Connector thread body (active). Issues a blocking connect() to
    // the caller-supplied remote endpoint, populates `accepted_fd` on
    // success, exits regardless. Connect failure is observable via
    // OpQueryTcpEstablished returning 0 (kernel never reaches
    // TCP_ESTABLISHED) — the dedicated worker is for asynchrony, not
    // for surfacing per-connect errors back through the UT channel.
    void tcpConnectorLoop(TcpListener *listener,
                          std::uint32_t remote_ip_be,
                          std::uint16_t remote_port);

    std::mutex                                                  tcp_mu_;
    std::map<std::uint8_t, std::unique_ptr<TcpListener>>        tcp_listeners_;
    std::uint8_t                                                next_tcp_socket_id_ = 1;

    // Compute the directed broadcast for this DUT's primary non-lo
    // IPv4 interface. ADDRESSING_02's silent-discard behaviour gates
    // on this value. Populated at start() via getifaddrs().
    std::uint32_t iface_bcast_be_ = 0;
    std::uint32_t iface_ip_be_    = 0;

    // §4.5 IPv4 Link-Local Autoconfiguration support. The iface name
    // and MAC are needed for AF_PACKET SOCK_RAW frame injection
    // (RFC 3927 ARP Probe / Announce + the precondition DHCPDISCOVER).
    // Populated alongside iface_ip_be_ at start().
    std::string                 iface_name_;
    std::array<std::uint8_t, 6> dut_mac_{};
    LinklocalAutoconf           linklocal_autoconf_;

    // §4.7 DHCPv4 client (full lifecycle: DISCOVER → OFFER → REQUEST
    // → ACK → BOUND). Distinct from `linklocal_autoconf_`'s 1-shot
    // DHCPDISCOVER which models "DHCP fail → fall back to LL".
    //
    // §4.7.6.5 USAGE_01 / RFC 2131 §3.6: a client with multiple network
    // interfaces uses DHCP through each interface independently. Vector
    // is sized at start() to match the count of non-loopback up AF_INET
    // ifaces sorted by name; index 0 = primary (lexicographically
    // smallest), index 1 = secondary (USAGE_01's DIface-1). The legacy
    // single-iface case lands index 0; vector is never resized after
    // start() so dispatch can index directly without locking.
    std::vector<std::unique_ptr<Dhcpv4Client>> dhcpv4_clients_;

    int data_fd_ = -1;
    int ut_fd_   = -1;
    std::thread data_thread_;
    std::thread ut_thread_;
    std::atomic<bool> stop_requested_{false};

    // Single-slot log: ADDRESSING_01/02 is a one-shot "did you just
    // receive anything?" check, so the last receipt per
    // (listen_port, dst_ip) is all that matters. More than a handful
    // of slots would invite staleness bugs with no observability
    // benefit. FRAGMENTS_05 does not consult this log at all.
    std::mutex log_mu_;
    ReceiveRecord last_receipt_{};

    // §4.6.5.5 UDP_USER_INTERFACE_01 backend: bind `count` UDP
    // SOCK_DGRAM sockets to (INADDR_ANY, ephemeral port=0). Returns
    // the actual number successfully bound. Each fd is appended to
    // `udp_receive_ports_`; `stop()` closes them in destruction order.
    // Single mutex guards the vector — concurrent calls are serialized
    // (the UT RPC server thread is the sole writer in practice).
    std::uint8_t createUdpReceivePorts(std::uint8_t count);

    std::mutex                udp_receive_ports_mu_;
    std::vector<int>          udp_receive_ports_;
};

}  // namespace tc8::dut
