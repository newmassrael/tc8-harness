#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "tc8/testability_protocol.h"

namespace tc8::stimulus {

// Tester-side AUTOSAR Testability Protocol client (PRS Testability TC 1.2.0,
// PRS_TPSP §6). The standard counterpart to the in-house opcode Upper Tester
// (upper_tester_client.h): it drives a DUT that implements the standard
// testability service over SOME/IP, so the harness is not limited to DUTs
// speaking our private opcodes. Wire framing + constants are the SSOT in
// include/tc8/testability_protocol.h; this layer adds the socket round trip
// and the GENERAL-group typed primitives.

// Configuration for one testability DUT endpoint.
struct TestabilityConfig {
    std::uint16_t service_id = testability::kDefaultServiceId;  // PRS_TPSP §6.1 SID
    std::uint32_t dut_ip_be = 0;                                // DUT IPv4 (network byte order)
    std::uint16_t dut_port = testability::kDefaultPort;         // PRS_TPSP §5.1 deployment port
    bool use_tcp = false;                                       // false = UDP (default), true = TCP
};

// Decoded testability response (PRS_TPSP §6.1 / PRS_TPSP §6.2). `ok` is false on socket error,
// timeout, a short/garbled reply, or a frame that is not a Response to this
// request. `tid` / `rid` are the raw testability bytes — note RID carries
// testability-specific values (0xFF E_NTF, 0xFC E_INV, ...) outside the
// SOME/IP standard return-code range, so they are kept as raw uint8.
struct TestabilityResponse {
    bool ok = false;
    std::uint8_t tid = 0;           // PRS_TPSP §6.2 message type id (0x80 on a well-formed response)
    std::uint8_t rid = 0;           // PRS_TPSP §6.8 result id
    std::vector<std::uint8_t> dat;  // PRS_TPSP §6.7 parameter data (payload after the 16-byte header)

    // A primitive that both reached the DUT and returned E_OK (PRS_TPSP §6.8).
    bool eok() const { return ok && rid == testability::kRidEOk; }
};

// Generic engine — the extension surface OEM-specific typed primitives build
// on. Frames one testability call (GID/PID + DAT) as a SOME/IP request, sends
// it over a kernel-routed socket (SOCK_DGRAM, or SOCK_STREAM when
// cfg.use_tcp), and blocks for the response. `src_ip_be` (0 = kernel-chosen)
// binds the source address — same contract as pingUpperTester's src bind.
// Returns ok=false on any transport or parse failure.
TestabilityResponse testabilityCall(const TestabilityConfig &cfg, std::uint8_t gid,
                                    std::uint8_t pid,
                                    const std::vector<std::uint8_t> &dat = {},
                                    int timeout_ms = 1000, std::uint32_t src_ip_be = 0);

// ── PRS_TPSP §6.10 GENERAL group typed wrappers (the standard, in-tree primitives) ──

struct TestabilityVersion {
    std::uint16_t major = 0;
    std::uint16_t minor = 0;
    std::uint16_t patch = 0;
};

// GET_VERSION (GENERAL / PID 0x01). Returns nullopt on transport failure or a
// malformed response; otherwise the DUT's reported testability protocol
// version (response DAT = major/minor/patch, uint16 x3, big-endian).
std::optional<TestabilityVersion> testabilityGetVersion(const TestabilityConfig &cfg,
                                                        int timeout_ms = 1000,
                                                        std::uint32_t src_ip_be = 0);

// START_TEST (GENERAL / PID 0x02) — no request parameters (PRS_TPSP §6.10 entry tag).
TestabilityResponse testabilityStartTest(const TestabilityConfig &cfg, int timeout_ms = 1000,
                                         std::uint32_t src_ip_be = 0);

// END_TEST (GENERAL / PID 0x03) — request DAT = tcId (uint16) + tsName (text,
// PRS_TPSP §6.7.5.2: UTF-8 with BOM and null termination wrapped in a vint8). Resets
// the Upper Tester (closes sockets, clears buffers, terminates active SPs).
TestabilityResponse testabilityEndTest(const TestabilityConfig &cfg, std::uint16_t tc_id,
                                       const std::string &ts_name, int timeout_ms = 1000,
                                       std::uint32_t src_ip_be = 0);

// ── PRS_TPSP §6.10 socket-group typed wrappers (the standard, in-tree primitives) ──
//
// Mandatory standard service primitives, provided in-tree so a consumer drives
// a conformant DUT through configuration alone — the OEM does not hand-write
// these wrappers. Only non-standard / OEM-specific SPs build directly on the
// generic testabilityCall engine. Primitives whose wire shape is identical
// across UDP and TCP take a `gid`; those whose parameters differ by group
// (SEND_DATA) or that are TCP-only (CONNECT / LISTEN_AND_ACCEPT) are split.

// CREATE_AND_BIND (UDP/TCP / PID 0x01): create a socket in group `gid`,
// optionally bound to (local_addr_be, local_port). local_port 0xFFFF == PORT_ANY
// (kernel-assigned); local_addr_be 0 == INADDR_ANY. Returns the DUT socketId on
// E_OK, else nullopt. The request shape is group-independent (PRS_TPSP §6.10).
std::optional<std::uint16_t> testabilityCreateAndBind(const TestabilityConfig &cfg,
                                                      std::uint8_t gid, bool do_bind,
                                                      std::uint16_t local_port,
                                                      std::uint32_t local_addr_be,
                                                      int timeout_ms = 1000,
                                                      std::uint32_t src_ip_be = 0);

// SEND_DATA (UDP / PID 0x02): connectionless transmit of `data` (repeated up to
// total_len bytes) to (dest_addr_be, dest_port).
TestabilityResponse testabilityUdpSendData(const TestabilityConfig &cfg, std::uint16_t socket_id,
                                           std::uint16_t total_len, std::uint16_t dest_port,
                                           std::uint32_t dest_addr_be,
                                           const std::vector<std::uint8_t> &data,
                                           int timeout_ms = 1000, std::uint32_t src_ip_be = 0);

// CONNECT (TCP / PID 0x05): active-open `socket_id` to (dest_addr_be, dest_port).
TestabilityResponse testabilityTcpConnect(const TestabilityConfig &cfg, std::uint16_t socket_id,
                                          std::uint16_t dest_port, std::uint32_t dest_addr_be,
                                          int timeout_ms = 1000, std::uint32_t src_ip_be = 0);

// SEND_DATA (TCP / PID 0x02): transmit `data` on the connected socket, repeated
// up to total_len bytes (PRS_TPSP §6.10; total_len < data sends data in full).
TestabilityResponse testabilityTcpSendData(const TestabilityConfig &cfg, std::uint16_t socket_id,
                                           std::uint16_t total_len, std::uint8_t flags,
                                           const std::vector<std::uint8_t> &data,
                                           int timeout_ms = 1000, std::uint32_t src_ip_be = 0);

// CLOSE_SOCKET (UDP/TCP / PID 0x00): close the DUT socket. `gid` selects the
// group; the request shape — socketId(uint16) — is identical for both.
TestabilityResponse testabilityCloseSocket(const TestabilityConfig &cfg, std::uint8_t gid,
                                           std::uint16_t socket_id, int timeout_ms = 1000,
                                           std::uint32_t src_ip_be = 0);

// CLOSE_SOCKET with abort=true (TCP / PID 0x00): an abortive close — the stack
// closes the socket immediately with a RST, not waiting for outstanding
// transmissions/acknowledgements (PRS_TPSP §6.10 CLOSE_SOCKET abort param). The
// request appends the abort byte the graceful testabilityCloseSocket omits.
TestabilityResponse testabilityAbortSocket(const TestabilityConfig &cfg, std::uint8_t gid,
                                           std::uint16_t socket_id, int timeout_ms = 1000,
                                           std::uint32_t src_ip_be = 0);

// SHUTDOWN (UDP/TCP / PID 0x07): half-close the DUT socket in the direction
// `type_id` (testability::kShutdownRd/Wr/RdWr) — the fd lives on, unlike
// CLOSE_SOCKET. `gid` selects the group; the request shape —
// socketId(uint16) + typeId(uint8) — is identical for both.
TestabilityResponse testabilityShutdown(const TestabilityConfig &cfg, std::uint8_t gid,
                                        std::uint16_t socket_id, std::uint8_t type_id,
                                        int timeout_ms = 1000, std::uint32_t src_ip_be = 0);

// LISTEN_AND_ACCEPT (TCP / PID 0x04), listen-only: mark `listen_socket_id` (a
// bound TCP socket) as listening with backlog `max_con` and return the
// synchronous E_OK Response — WITHOUT awaiting the asynchronous accept Event.
// The DUT is left in LISTEN so the caller can drive its own raw tester-side
// stimulus and observe the DUT's wire responses (invalid-flag SYNs, OTW RSTs)
// for cases that never complete a kernel handshake. Use
// testabilityTcpListenAndAccept when an accepted connection IS expected.
// Same request shape (listenSocketId(u16) + maxCon(u16)) and SP as that wrapper
// — the SSOT for the LISTEN_AND_ACCEPT request framing lives in this .cpp.
TestabilityResponse testabilityTcpListen(const TestabilityConfig &cfg,
                                         std::uint16_t listen_socket_id, std::uint16_t max_con,
                                         int timeout_ms = 1000, std::uint32_t src_ip_be = 0);

// The asynchronous accept Event a DUT emits per connection accepted on a
// LISTEN_AND_ACCEPT socket (PRS_TPSP §6.10). `received` is false if no Event
// arrived within the timeout (or the listen request itself failed).
struct TestabilityAcceptEvent {
    bool received = false;
    std::uint16_t listen_socket_id = 0;
    std::uint16_t new_socket_id = 0;   // socket id of the accepted connection
    std::uint16_t client_port = 0;     // accepted peer's port
    std::uint32_t client_addr_be = 0;  // accepted peer's IPv4 (network byte order)
};

// LISTEN_AND_ACCEPT (TCP / PID 0x04): mark `listen_socket_id` (a bound TCP
// socket) as listening with backlog `max_con`, then wait for the DUT's
// asynchronous accept Event. The request, its response, and the Event share one
// UDP socket so the DUT's Event reaches the tester. `on_listening` is invoked
// once the listen returns E_OK and before the Event wait — the caller triggers
// the incoming connection there (e.g. opens a TCP connection to the DUT's
// listen port). Returns the parsed Event (received=false on listen failure or
// Event timeout). Uses the UDP control transport (cfg.use_tcp is ignored).
TestabilityAcceptEvent testabilityTcpListenAndAccept(const TestabilityConfig &cfg,
                                                     std::uint16_t listen_socket_id,
                                                     std::uint16_t max_con,
                                                     const std::function<void()> &on_listening,
                                                     int resp_timeout_ms = 1000,
                                                     int event_timeout_ms = 2000,
                                                     std::uint32_t src_ip_be = 0);

// The forward Events collected from a TCP RECEIVE_AND_FORWARD socket
// (PRS_TPSP §6.10), reassembled into one buffer. `ok` is true when the arm
// request returned E_OK; `payload` is empty if no Event arrived within the
// timeout. TCP carries fullLen + payload only (no srcPort/srcAddr —
// connection-oriented).
struct TestabilityForwardResult {
    bool ok = false;                    // arm request round-tripped and returned E_OK
    std::uint16_t drop_cnt = 0;         // inactive-phase bytes consumed before the arm
    std::uint16_t full_len = 0;         // total length the DUT received across the Events
    std::vector<std::uint8_t> payload;  // reassembled forwarded payload (<= max_len)
};

// RECEIVE_AND_FORWARD (TCP / PID 0x03): arm `socket_id` to forward inbound
// stream data as Events. The request consumes the bytes queued before the call
// (returned as drop_cnt) to reopen the receive window and returns E_OK;
// `on_armed` is then invoked to drive the inbound data. The DUT emits one
// forward Event per recv() (fullLen + payload, payload capped at `max_fwd`);
// the Events are accumulated on the same socket until `max_len` bytes are
// gathered or the event budget expires, so a stream split across the DUT's
// recv()s reassembles into one buffer (mirrors the opcode OpReceiveTcpData
// recv-loop). max_len 0xFFFF == limitless, which collects a single Event. Uses
// the UDP control transport.
TestabilityForwardResult testabilityReceiveAndForward(
    const TestabilityConfig &cfg, std::uint16_t socket_id, std::uint16_t max_fwd,
    std::uint16_t max_len, const std::function<void()> &on_armed, int resp_timeout_ms = 1000,
    int event_timeout_ms = 2000, std::uint32_t src_ip_be = 0);

// ECHO_REQUEST (ICMP / PID 0x00, PRS_TPSP §6.10): issue a single ICMP Echo
// Request from the DUT toward `dest_addr_be` over interface `iface` (empty =>
// kernel-chosen egress). `payload` is the Echo data. Fire-and-forget — the DUT
// returns E_OK once the request is emitted, or E_IIF for an unknown interface.
TestabilityResponse testabilityEchoRequest(const TestabilityConfig &cfg, const std::string &iface,
                                           std::uint32_t dest_addr_be,
                                           const std::vector<std::uint8_t> &payload,
                                           int timeout_ms = 1000, std::uint32_t src_ip_be = 0);

// ECHO_REQUEST (ICMPv6 / GID 0x04, PID 0x00, PRS_TPSP §6.10): the IPv6 sibling of
// testabilityEchoRequest — `dest_addr16` is the 16-byte destination (wire order).
TestabilityResponse testabilityEchoRequestV6(const TestabilityConfig &cfg, const std::string &iface,
                                             const std::uint8_t dest_addr16[16],
                                             const std::vector<std::uint8_t> &payload,
                                             int timeout_ms = 1000, std::uint32_t src_ip_be = 0);

}  // namespace tc8::stimulus
