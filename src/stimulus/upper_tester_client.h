#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "stimulus/boot_timing.h"

namespace tc8::stimulus {

// Builder helpers for tester-side Upper Tester request frames (§4.8.5).
// Each helper returns the UT-protocol payload bytes — wrap in a UDP
// datagram + IPv4 frame before injecting via AF_PACKET SOCK_RAW, or
// hand to a normal SOCK_DGRAM socket.

// Build a 0x01 GetReceivedUdp request.
//
//   <opcode:u8=0x01> <req_id:u8> <listen_port:u16> <expected_dst_ip:u32>
//
// Fixed size: 1 + 1 + 2 + 4 = 8 bytes.
std::vector<std::uint8_t> buildGetReceivedUdpRequest(
    std::uint8_t  req_id,
    std::uint16_t listen_port,
    std::uint32_t expected_dst_ip_be);

// Build a 0x02 TriggerSendUdp request.
//
//   <opcode:u8=0x02> <req_id:u8> <src_port:u16> <dst_ip:u32>
//   <dst_port:u16> <payload_len:u16> <payload[]>
//   [<src_ip_override_be:u32>]   // optional, append-only
//
// The builder copies `payload` bytes verbatim. `payload_len` must fit
// in `ut::kMaxPayload` — larger values silently truncate the UT
// payload at the tc8-dut parser, which is enforced by a GTest in
// `upper_tester_client_test`.
//
// `src_ip_override_be` (default 0) selects the tc8-dut's transient
// socket bind source. 0 = legacy behaviour (bind to primary iface IP,
// no trailer emitted on the wire — byte-identical to pre-extension
// callers). Non-zero appends the 4-byte trailer; tc8-dut binds the
// socket to (override, src_port). Used by §4.6.5.5
// UDP_USER_INTERFACE_07 to verify the spec-mandated caller-specified
// Source IP axis with the DIface-0 alias literal.
std::vector<std::uint8_t> buildTriggerSendUdpRequest(
    std::uint8_t        req_id,
    std::uint16_t       src_port,
    std::uint32_t       dst_ip_be,
    std::uint16_t       dst_port,
    const std::uint8_t *payload,
    std::uint16_t       payload_len,
    std::uint32_t       src_ip_override_be = 0);

// Build a 0x03 OpenTcpSocket request (passive). tc8-dut creates a
// listening SOCK_STREAM bound to <local_port> and returns a socket_id
// the caller hands to subsequent Close / QueryEstablished requests.
//
//   <opcode:u8=0x03> <req_id:u8> <type:u8=Passive> <local_port:u16>
//
// Fixed size: 1 + 1 + 1 + 2 = 5 bytes.
std::vector<std::uint8_t> buildOpenTcpSocketPassiveRequest(
    std::uint8_t  req_id,
    std::uint16_t local_port);

// Build a 0x03 OpenTcpSocket request (active). tc8-dut creates a
// SOCK_STREAM bound to (iface_ip, <local_port>) and connect()s to
// <remote_ip>:<remote_port>; success is reported when the kernel
// completes the 3-way handshake (TCP_ESTABLISHED). Used by §4.8.6.1
// BASICS_06+ where the DUT initiates the connection under tester
// direction.
//
//   <opcode:u8=0x03> <req_id:u8> <type:u8=Active>
//   <local_port:u16> <remote_ip:u32 BE> <remote_port:u16>
//
// Fixed size: 1 + 1 + 1 + 2 + 4 + 2 = 11 bytes.
std::vector<std::uint8_t> buildOpenTcpSocketActiveRequest(
    std::uint8_t  req_id,
    std::uint16_t local_port,
    std::uint32_t remote_ip_be,
    std::uint16_t remote_port);

// Build a 0x04 CloseTcpSocket request.
//
//   <opcode:u8=0x04> <req_id:u8> <socket_id:u8>
//
// Fixed size: 1 + 1 + 1 = 3 bytes.
std::vector<std::uint8_t> buildCloseTcpSocketRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id);

// Build a 0x05 QueryTcpEstablished request. tc8-dut replies with a
// boolean indicating whether the listener with `socket_id` has accepted
// a connection — i.e. progressed past the SYN-RCVD state.
//
//   <opcode:u8=0x05> <req_id:u8> <socket_id:u8>
//
// Fixed size: 1 + 1 + 1 = 3 bytes.
std::vector<std::uint8_t> buildQueryTcpEstablishedRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id);

// Build a 0x13 QueryTcpInfo request. tc8-dut reads `struct tcp_info`
// off the connected fd identified by `socket_id` via
// `getsockopt(SOL_TCP, TCP_INFO)` and replies with four fields the
// §4.8.6.11 TCP_RETRANSMISSION_TO cluster verdicts on without
// depending on pcap timing of retransmits — see
// `tc8::ut::OpQueryTcpInfo` documentation in
// `include/tc8/upper_tester_protocol.h`.
//
//   <opcode:u8=0x13> <req_id:u8> <socket_id:u8>
//
// Fixed wire size: 1 + 1 + 1 = 3 bytes.
std::vector<std::uint8_t> buildQueryTcpInfoRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id);

// Build a 0x06 SendTcpData request. tc8-dut writes `payload` bytes to
// the connected fd identified by `socket_id`; Linux frames the bytes
// into outbound segment(s) the tester observes via pcap. Used by
// §4.8.6.2 TCP_CHECKSUM_03 to drive the spec-mandated DUT-side SEND.
//
//   <opcode:u8=0x06> <req_id:u8> <socket_id:u8>
//   <payload_len:u16> <payload[]>
//
// Wire size: 5 + payload_len. payload_len is clamped at kMaxPayload to
// match the TriggerSendUdp builder convention; oversize input silently
// truncates rather than overflowing the parser bound.
std::vector<std::uint8_t> buildSendTcpDataRequest(
    std::uint8_t        req_id,
    std::uint8_t        socket_id,
    const std::uint8_t *payload,
    std::uint16_t       payload_len);

// Build a 0x07 ReceiveTcpData request. tc8-dut blocks in ::recv()
// up to `timeout_ms`, accumulating up to `expected_len` bytes into a
// buffer it returns in the Confirmation body. Used by §4.8.6.8
// TCP_CLOSING_07/_08 to drive the spec-mandated DUT-side RECEIVE
// call.
//
//   <opcode:u8=0x07> <req_id:u8> <socket_id:u8>
//   <expected_len:u16> <timeout_ms:u16>
//
// Fixed wire size: 1 + 1 + 1 + 2 + 2 = 7 bytes. expected_len is
// clamped at kMaxPayload to keep the response Confirmation under the
// 256-byte budget.
std::vector<std::uint8_t> buildReceiveTcpDataRequest(
    std::uint8_t  req_id,
    std::uint8_t  socket_id,
    std::uint16_t expected_len,
    std::uint16_t timeout_ms);

// Build a 0x08 ShutdownTcpSocketWr request. tc8-dut calls
// shutdown(SHUT_WR) on the connected fd identified by `socket_id` —
// kernel emits FIN, socket transitions EST→FW1, read side stays
// open. Used by §4.8.6.8 TCP_CLOSING_07/_08 where the spec needs
// "CLOSE then RECEIVE" semantics.
//
//   <opcode:u8=0x08> <req_id:u8> <socket_id:u8>
//
// Fixed wire size: 1 + 1 + 1 = 3 bytes.
std::vector<std::uint8_t> buildShutdownTcpSocketWrRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id);

// Build a 0x09 AbortTcpSocket request. tc8-dut applies SO_LINGER
// {l_onoff=1, l_linger=0} then calls ::close() on the connected fd —
// Linux emits RST instead of FIN and disposes the socket immediately.
// Used by §4.8.6.5 TCP_CALL_ABORT_02/_03 where the spec drives the
// DUT application to issue an ABORT call.
//
//   <opcode:u8=0x09> <req_id:u8> <socket_id:u8>
//
// Fixed wire size: 1 + 1 + 1 = 3 bytes.
std::vector<std::uint8_t> buildAbortTcpSocketRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id);

// Build a 0x0B ReceiveTcpDataOob request. tc8-dut calls
// `::recv(fd, buf, expected_len, MSG_OOB)` blocking up to
// `timeout_ms`; the response carries the urgent bytes Linux
// delivered through the out-of-band queue. Used by §4.8.6.14
// TCP_URGENT_PTR_04 to verify the DUT's RECEIVE call returns only
// the urgent data (RFC 793 §3.7 interface MUST).
//
//   <opcode:u8=0x0B> <req_id:u8> <socket_id:u8>
//   <expected_len:u16> <timeout_ms:u16>
//
// Same wire shape as OpReceiveTcpData (0x07); only the tc8-dut
// recv() flag differs (MSG_OOB vs 0). Fixed wire size: 7 bytes.
std::vector<std::uint8_t> buildReceiveTcpDataOobRequest(
    std::uint8_t  req_id,
    std::uint8_t  socket_id,
    std::uint16_t expected_len,
    std::uint16_t timeout_ms);

// Build a 0x0A SendTcpDataPattern request. tc8-dut allocates a
// `total_len`-byte buffer filled with `pattern` and writes it via
// ::send() to the connected fd identified by `socket_id`. Used by
// §4.8.6.9 TCP_MSS_OPTIONS_06/_09/_10 where MSS verification needs
// the DUT's send buffer to overflow its negotiated MSS so Linux
// segments the payload — that requires bulk data (1500+ B) which
// cannot ride the UT UDP request without exceeding MTU. Bulk
// generation lives tc8-dut-side; the wire request stays compact.
//
//   <opcode:u8=0x0A> <req_id:u8> <socket_id:u8> <pattern:u8>
//   <total_len:u16>
//
// Fixed wire size: 1 + 1 + 1 + 1 + 2 = 6 bytes.
std::vector<std::uint8_t> buildSendTcpDataPatternRequest(
    std::uint8_t  req_id,
    std::uint8_t  socket_id,
    std::uint8_t  pattern,
    std::uint16_t total_len);

// Build a 0x0C StartLLAutoconf request — kicks off the tc8-dut's
// RFC 3927 IPv4 Link-Local state machine for §4.5 cases. The tc8-dut
// emits one DHCPDISCOVER (the precondition step "DUT: Sends
// DHCPDISCOVER Message"), sleeps `dhcp_timeout_ms` to model "no DHCP
// server replied", then begins PROBE/ANNOUNCE on a randomly-chosen
// 169.254.X.Y address (X in [1, 254] per RFC 3927 §2.1 reserved-range
// rule).
//
//   <opcode:u8=0x0C> <req_id:u8>
//   <dhcp_timeout_ms:u16>     <probe_wait_ms:u16>
//   <probe_min_ms:u16>        <probe_max_ms:u16>
//   <announce_wait_ms:u16>    <announce_interval_ms:u16>
//   <rate_limit_interval_ms:u16>
//
// Fixed wire size: 1 + 1 + 14 = 16 bytes.
//
// All seven timings are in milliseconds. The first six are the
// PROBE/ANNOUNCE cadence: pass spec defaults (PROBE_WAIT 1000,
// PROBE_MIN 1000, PROBE_MAX 2000, ANNOUNCE_WAIT 2000,
// ANNOUNCE_INTERVAL 2000) for §4.5.6.2 ADDRESS_SELECTION_09/_10
// timing-cadence cases; pass shorter values (200-400 ms range) for
// observation cases that only need the FIRST Probe / Announce.
//
// `rate_limit_interval_ms` is the RFC 3927 §2.2.1 RATE_LIMIT_INTERVAL —
// silence window after MAX_CONFLICTS=10 conflicts. Spec default
// 60 000 ms; §4.5.6.2 _14 fast envelope uses 3 000 ms so the SCXML
// deadline accommodates 10 conflict cycles + one full silence window.
// Cases that never reach the conflict cap (everything but _14/_15)
// pass any value — the parameter is irrelevant on the success path.
std::vector<std::uint8_t> buildStartLLAutoconfRequest(
    std::uint8_t  req_id,
    std::uint16_t dhcp_timeout_ms,
    std::uint16_t probe_wait_ms,
    std::uint16_t probe_min_ms,
    std::uint16_t probe_max_ms,
    std::uint16_t announce_wait_ms,
    std::uint16_t announce_interval_ms,
    std::uint16_t rate_limit_interval_ms);

// Build a 0x0D QueryLLAddress request. tc8-dut replies with the
// committed LL address (or 0.0.0.0 if not yet committed) so a
// subsequent SCXML guard can pin `captured.target_proto_ip ==
// ut.linklocal_addr` for ANNOUNCING / NETWORK_PARTITIONS cases.
//
//   <opcode:u8=0x0D> <req_id:u8>
//
// Fixed wire size: 1 + 1 = 2 bytes.
std::vector<std::uint8_t> buildQueryLLAddressRequest(
    std::uint8_t req_id);

// Build a 0x0E AbortLLAutoconf request. tc8-dut stops and joins the
// state-machine thread, releases the chosen LL address. Used by case
// CLEANUP to prevent leftover LL state leaking into the next case.
//
//   <opcode:u8=0x0E> <req_id:u8>
//
// Fixed wire size: 1 + 1 = 2 bytes.
std::vector<std::uint8_t> buildAbortLLAutoconfRequest(
    std::uint8_t req_id);

// Build a 0x0F StartLLAutoconfBuggy request — fault-injection variant
// of OpStartLLAutoconf for §4.5.6.2 ADDRESS_SELECTION cluster A
// negative-case self-validation. Same seven timing knobs as 0x0C in
// the same byte order followed by a `flavor` byte that mutates one
// ARP Probe field per the `tc8::ut::kFlavor*` invariant table;
// tc8-dut applies the mutation uniformly across all three Probes the
// state machine emits. Announce-phase frames stay compliant.
//
//   <opcode:u8=0x0F> <req_id:u8>
//   <dhcp_timeout_ms:u16>     <probe_wait_ms:u16>
//   <probe_min_ms:u16>        <probe_max_ms:u16>
//   <announce_wait_ms:u16>    <announce_interval_ms:u16>
//   <rate_limit_interval_ms:u16>
//   <flavor:u8>
//
// Fixed wire size: 1 + 1 + 14 + 1 = 17 bytes.
//
// `rate_limit_interval_ms` has no observable effect on the negative
// cases — they finish in one PROBE attempt and never reach the
// MAX_CONFLICTS threshold — but matching the 0x0C wire shape lets
// the harness thread a single `Params` path through both opcodes.
std::vector<std::uint8_t> buildStartLLAutoconfBuggyRequest(
    std::uint8_t  req_id,
    std::uint16_t dhcp_timeout_ms,
    std::uint16_t probe_wait_ms,
    std::uint16_t probe_min_ms,
    std::uint16_t probe_max_ms,
    std::uint16_t announce_wait_ms,
    std::uint16_t announce_interval_ms,
    std::uint16_t rate_limit_interval_ms,
    std::uint8_t  flavor);

// Build a 0x10 StartDhcpClient request — kicks the tc8-dut's full
// DHCPv4 client lifecycle (DISCOVER → wait OFFER → REQUEST → wait
// ACK → BOUND). Distinct from 0x0C OpStartLLAutoconf (1-shot
// DISCOVER then LL fallback); the §4.7 lifecycle path persists xid
// across DISCOVER → REQUEST and never falls back to LL.
//
//   <opcode:u8=0x10> <req_id:u8>
//   <offer_wait_ms:u16>               <ack_wait_ms:u16>
//   <retry_count:u8>                  <retry_interval_ms:u16>
//   <nak_to_discover_min_ms:u16>      <nak_to_discover_max_ms:u16>
//   <arp_probe_listen_ms:u16>
//   <decline_to_discover_min_ms:u16>  <decline_to_discover_max_ms:u16>
//   <retx_first_ms:u16>               <retx_cap_ms:u16>
//   <retx_jitter_ms:u16>
//   <iface_index:u8>
//
// Fixed wire size: 1 + 1 + 24 = 26 bytes. Legacy 9 / 13 / 15 / 17 / 25-byte
// (S2..S6b / S9 / S10 / S12 / pre-S13) payloads are still accepted —
// DUT defaults every later slot to 0, preserving instant restart,
// skip-Probe, instant-restart-after-DECLINE, flat-retry, and
// primary-iface (index=0) behaviour.
//
// §4.7.6.9 INIT_ALLOC_01: nak_to_discover_min/max define the random
// wait the DUT applies between NAK ingestion (or lease expiry) and the
// next DHCPDISCOVER per RFC 2131 §4.4.1 SHOULD. Both default to 0.
//
// §4.7.6.9 INIT_ALLOC_08/_09/_10: arp_probe_listen_ms enables the
// post-BOUND ARP Probe + listen + DECLINE/Announce sequence per
// RFC 2131 §4.4.1. Default 0 = skip the sequence; 1500 ms is the
// fast-envelope harness toggle (Q4) shrinking spec ParamListenTime
// (10 s) into the SCE 14-22 s case_timeout budget.
//
// §4.7.6.3 ALLOCATING_08: decline_to_discover_min/max define the random
// wait the DUT applies between a DHCPDECLINE and the next DHCPDISCOVER
// per RFC 2131 §3.1 SHOULD. Both default to 0 (instant restart, used by
// ALLOCATING_07 + INIT_ALLOC_09 which only verify the MUST behaviour).
//
// §4.7.6.7 CM_12/_13: retx_first_ms / retx_cap_ms / retx_jitter_ms
// configure the exponential-backoff retransmission schedule per RFC
// 2131 §4.1. retx_first_ms == 0 (default) keeps legacy flat
// retry_interval_ms behaviour.
//
// §4.7.6.5 USAGE_01: `iface_index` selects which Dhcpv4Client instance
// the tc8-dut dispatches the start to. 0 (default) targets the primary
// iface (lexicographically smallest non-loopback up AF_INET name —
// veth-dut-W under smoke-test); 1 targets the second pair (DIface-1 /
// veth-dut2-W) brought up only when smoke-test.sh's NEED_SECOND_VETH
// path triggers (USAGE_01 inclusion).
std::vector<std::uint8_t> buildStartDhcpClientRequest(
    std::uint8_t  req_id,
    std::uint16_t offer_wait_ms,
    std::uint16_t ack_wait_ms,
    std::uint8_t  retry_count,
    std::uint16_t retry_interval_ms,
    std::uint16_t nak_to_discover_min_ms     = 0,
    std::uint16_t nak_to_discover_max_ms     = 0,
    std::uint16_t arp_probe_listen_ms        = 0,
    std::uint16_t decline_to_discover_min_ms = 0,
    std::uint16_t decline_to_discover_max_ms = 0,
    std::uint16_t retx_first_ms              = 0,
    std::uint16_t retx_cap_ms                = 0,
    std::uint16_t retx_jitter_ms             = 0,
    std::uint8_t  iface_index                = 0);

// Build a 0x11 QueryDhcpLease request. tc8-dut replies with the bound
// IPv4 address (yiaddr from the matched ACK) or 0 if not yet bound.
//
//   <opcode:u8=0x11> <req_id:u8>
//
// Fixed wire size: 1 + 1 = 2 bytes.
std::vector<std::uint8_t> buildQueryDhcpLeaseRequest(std::uint8_t req_id);

// Build a 0x12 AbortDhcpClient request. tc8-dut stops and joins the
// state-machine thread, clears the bound lease.
//
//   <opcode:u8=0x12> <req_id:u8>
//
// Fixed wire size: 1 + 1 = 2 bytes.
std::vector<std::uint8_t> buildAbortDhcpClientRequest(std::uint8_t req_id);

// Build a 0x14 CreateUdpReceivePorts request. tc8-dut binds `count`
// UDP SOCK_DGRAM sockets to (INADDR_ANY, ephemeral port=0) and
// returns the actual count successfully bound. Used by §4.6.5.5
// UDP_USER_INTERFACE_01 to verify the DUT's user interface allows
// dynamic creation of N receive ports per RFC 768 'User Interface'.
//
//   <opcode:u8=0x14> <req_id:u8> <count:u8>
//
// Fixed wire size: 1 + 1 + 1 = 3 bytes (request) /
//                  1 + 1 + 1 + 1 = 4 bytes (response carries
//                  <actual_count:u8> after the status byte).
std::vector<std::uint8_t> buildCreateUdpReceivePortsRequest(
    std::uint8_t req_id,
    std::uint8_t count);

// Build a 0x15 Ping request. Side-effect-free liveness + capability
// probe — the DUT answers with the highest opcode it implements.
//
//   <opcode:u8=0x15> <req_id:u8>
//
// Fixed wire size: 1 + 1 = 2 bytes (request) /
//                  1 + 1 + 1 + 1 = 4 bytes (response carries
//                  <max_opcode:u8> after the status byte).
std::vector<std::uint8_t> buildPingRequest(std::uint8_t req_id);

// Result of a successful OpPing round trip.
struct UtPingResult {
    // Highest UT opcode the DUT firmware implements (kMaxImplementedOpcode
    // for the reference tc8-dut). Lets a tester detect subset
    // implementations on OEM DUTs.
    std::uint8_t max_opcode;
};

// Blocking OpPing round trip over a plain SOCK_DGRAM socket (kernel
// routing decides the egress interface). Returns nullopt on socket
// error, timeout, or a malformed / non-OK response. Used by
// smoke-test.sh topology preflights via the `ut-ping` CLI subcommand —
// unlike the SOCK_RAW injection path below this needs no interface
// name, MAC, or CAP_NET_RAW.
std::optional<UtPingResult> pingUpperTester(std::uint32_t dut_ip_be,
                                            std::uint16_t dut_port = ut::kPort,
                                            int timeout_ms = 1000);

// One-shot sender: wrap `ut_payload` in a UDP datagram (RFC 768
// checksum) + IPv4 frame, and inject on `iface` via AF_PACKET SOCK_RAW.
// `dut_mac` is the DUT's hardware address — Linux dispatches by dst_ip
// on veth pairs, but setting the Eth dst correctly avoids learning
// quirks that confound concurrent ARP test cases.
//
// `tester_src_port` is the source port the outbound UDP datagram
// carries. The tc8-dut's UT response returns to that port, so the
// tester's pcap BPF filter narrows cleanly on `udp and port <tester_
// src_port>` or `port <ut::kPort>`.
int sendUpperTesterRequest(std::string_view iface,
                           std::uint32_t tester_ip_be,
                           std::uint32_t dut_ip_be,
                           const std::array<std::uint8_t, 6> &dut_mac,
                           std::uint16_t tester_src_port,
                           const std::vector<std::uint8_t> &ut_payload);

// DUT-side source port of the datagram a boot-cadence OpTriggerSendUdp
// asks for. Disjoint from the §4.6 UDP_FIELDS per-case literals (20001+)
// and from `ut::kDataPort` (20000) so a pcap reader can attribute the
// frame to the egress-provocation stimulus at a glance. The §4.2 SCXML
// guards never compare ports — only dst_ip and Eth-dst — so the value
// carries no verdict weight.
inline constexpr std::uint16_t kEgressBootDutSrcPort = 20010;

// Tester-side source port the boot-cadence UT request rides on; the UT
// response returns to it. Matches the §4.6 UDP_FIELDS convention
// (`kUdpFieldsTesterSrcPort`) so tester-originated UT traffic shares one
// port across spec areas.
inline constexpr std::uint16_t kEgressBootTesterSrcPort = 20100;

// High-level TESTER boot-time DUT-egress provocation used by the §4.2.4
// entry-learning / cache-use cases. Renders the spec step "DUT
// CONFIGURE: Configure DUT to send a UDP Message from <DIface-0>
// (src=<DIface-0-IP>, dst=<HOST-1-IP>)" literally as a UT 0x02
// OpTriggerSendUdp request (replacing the historical SubscribeEventgroup
// → Nack substitute that predated the UT UDP opcodes).
//
// Each emit injects one UT request via AF_PACKET; a live DUT answers
// with (a) the UT response datagram (DUT:`ut::kPort` →
// tester:`kEgressBootTesterSrcPort`) and (b) the triggered datagram
// (DUT:`kEgressBootDutSrcPort` → tester:`ut::kDataPort`). Both are
// DUT-originated UDP to HOST-1-IP, so either satisfies the spec's
// egress observation — and both exercise the DUT's ARP resolution of
// `tester_ip_be` the §4.2 verdicts hang on.
//
// Emit cadence mirrors `emitSubscribeEventgroupBoot`: sleep
// `timing.initial_wait` for DUT bring-up, then `timing.total_emits`
// requests spaced `timing.retry_interval` apart to ride out a DUT whose
// UT server is not yet listening (the raw-injected request is lost, not
// queued). Blocks the calling thread for the full envelope. Returns 0
// if every injection succeeded, or the first negative return from
// `sendUpperTesterRequest`.
//
// `tester_ip_be` / `dut_ip_be` / `dut_mac` are TOPOLOGY identities, not
// SCXML expectations: §4.2 callers pass `cfg.ipv4.tester_ip` +
// `cfg.arp.dut_real_*` (the same split as the §4.6 UDP traits and the
// `dut_real_ip` vs `dut_iface_ip` precedent in `ArpExpectations`).
// Passing the `arp.tester_ip` expectation knob instead would let a
// `--negative` override silence the DUT (request sourced from / reply
// routed to an unroutable IP) rather than shift only the SCXML
// comparison — exactly the failure mode the ARP_03/05/15 negative rows
// exist to catch.
int emitTriggerSendUdpBoot(std::string_view iface,
                           std::uint32_t tester_ip_be,
                           std::uint32_t dut_ip_be,
                           const std::array<std::uint8_t, 6> &dut_mac,
                           const BootTiming &timing = {});

}  // namespace tc8::stimulus
