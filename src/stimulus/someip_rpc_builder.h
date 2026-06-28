#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "someip/protocol.h"             // MessageType / ReturnCode (shared wire constants).
#include "stimulus/someip_sd_builder.h"  // BootTiming for shared envelope.

namespace tc8::stimulus {

// Descriptor for one SOME/IP RPC message — every header field the tester
// sets on the wire, plus the payload. The RPC family (Request 0x00,
// RequestNoReturn 0x01, Response 0x80, Error 0x81) shares one 16-byte header
// layout, so this single type backs all of build{MethodRequest,
// MethodResponse, MethodError}; `message_type` discriminates. Defaults match
// tc8-dut's echoUINT8 Request (METHOD-ID-1-SI-1, msg_type=Request,
// return_code=E_OK, ifVer=1) so request cases that override only a subset
// stay terse; the reply builders set `message_type` themselves.
//
// `client_id` and `session_id` together form the SOME/IP §4.7.1 Request ID
// pair: on a request the tester sets it and the DUT echoes it back in the
// Response/Error; on a tester-built reply, set them to echo the captured
// request so the peer correlates it. Cases asserting Request-ID echo (e.g.
// RPC_19) override these to non-default sentinels; others leave the tester
// defaults (0x0000 / 0x0001).
//
// `message_type` and `return_code` are explicit so cases that exercise
// non-Request shapes (Fire&Forget = 0x01, deliberately-bad return_code =
// 0xC0) can drive them without re-implementing the builder.
struct SomeIpRpcMessage {
    std::uint16_t service_id = 0xF4E7;          // SERVICE-ID-1 (tc8-dut default).
    std::uint16_t method_id = 0x0008;           // METHOD-ID-1-SI-1 (echoUINT8 — tc8-dut UDP method).
    std::uint16_t client_id = 0x0000;           // §5.1.5.1 FORMAT_01: tester defaults to 0x0000.
    std::uint16_t session_id = 0x0001;          // SOME/IP §4.7.2: starts at 0x0001 per request stream.
    std::uint8_t protocol_version = 0x01;       // SOME/IP V1.1 fixed.
    std::uint8_t interface_version = 0x01;      // ets.fidl version.major.
    someip::MessageType message_type = someip::MessageType::REQUEST;  // RPC message kind discriminator.
    someip::ReturnCode return_code = someip::ReturnCode::E_OK;        // E_OK for request/response; non-E_OK for error.
    std::vector<std::uint8_t> payload{};        // CommonAPI-serialised method args.

    // Override for the SOME/IP Length field (4 bytes from Request ID
    // through end of payload). When set, replaces the otherwise-computed
    // `8 + payload.size()` value, letting cases drive deliberate
    // header/payload mismatches. §5.1.6 SOMEIP_ETS_001 uses this to assert
    // the DUT rejects a Request whose Length claims more bytes than the
    // UDP datagram actually delivers (PRS_SOMEIP_00099); ETS_002 drives a
    // smaller mismatch via the same axis. Default `std::nullopt` keeps the
    // self-consistent length for happy-path cases.
    std::optional<std::uint32_t> length_override{};

    // Raw-byte overrides for negative cases that must emit an off-enum value
    // (same idiom as length_override): when set, the builder emits the raw
    // byte instead of the typed field — e.g. message_type 0x07 (reserved),
    // return_code 0xC0 (top bits set) or 0x1F.
    std::optional<std::uint8_t> message_type_override{};
    std::optional<std::uint8_t> return_code_override{};
};

// Builds a 16-byte SOME/IP header plus the caller-supplied payload as the
// UDP payload of a SOME/IP Method Request. Length field = 8 + payload.size()
// (bytes from Request ID through the end). Wire byte order is network (BE)
// per SOME/IP §4.1.
std::vector<std::uint8_t> buildMethodRequest(const SomeIpRpcMessage &t);

// --- Tester server-role reply builders (SOMEIPCLT topology) ---
//
// In the SOMEIPCLT cases the tester offers the service and the DUT is the
// client: the DUT issues a Method Request and the tester answers. Per
// PRS_SOMEIP_00701 a Request (message type 0x00) is answered by a Response
// (0x80) when no error occurred, or an Error (0x81) when one did. The reply
// echoes the request's Message ID (service_id + method_id) and Request ID
// (client_id + session_id) so the DUT correlates it to its outstanding call
// (SOME/IP §4.7.1 Request ID); build each reply from the captured request's
// identity.
//
// Both reuse the `buildMethodRequest` header core (one SOME/IP framing SSOT)
// and honour `length_override`, so the CLT_RPC negative cases drive
// deliberately-malformed replies through the same axis as the request side.

// Method Response (PRS_SOMEIP_00701 message type 0x80). Forces message_type
// to RESPONSE; `t.return_code` is emitted as-is and may carry any code from
// PRS_SOMEIP_00191 (defaults to E_OK 0x00).
std::vector<std::uint8_t> buildMethodResponse(SomeIpRpcMessage t);

// Method Error (PRS_SOMEIP_00701 message type 0x81). Forces message_type to
// ERROR; `t.return_code` is emitted as-is. PRS_SOMEIP_00757 requires it not
// be E_OK, so a happy-path Error sets `t.return_code` to a non-zero code
// (e.g. E_NOT_OK 0x01). The wrapper does NOT auto-correct the struct default
// of E_OK, so a negative case can drive the spec-forbidden Error+E_OK shape.
std::vector<std::uint8_t> buildMethodError(SomeIpRpcMessage t);

// Destination of a Method Request — the DUT's per-method endpoint. A pure
// value type with no implicit default: the endpoint is always topology-
// derived, never baked in. The conformance literal (172.16.0.2:30502) has
// its single source of truth in the `--expect` surface / vsomeip.json, not
// here. Build it via `tc8::sce::someipUdp/TcpMethodDest`, which sources it
// from `cfg.someip`; a zero-initialised value (0.0.0.0:0) is an unconfigured
// sentinel that fails loud on connect rather than silently targeting a
// hardcoded address.
struct MethodRequestDestination {
    // IPv4 in network byte order (matches `Ipv4Endpoint::ipv4_be` and
    // cfg.someip.dut_iface_ip, both NBO via inet_pton).
    std::uint32_t ipv4_be = 0;
    // Host order; the emitter applies htons.
    std::uint16_t port = 0;
};

// Tester-side Method Request emit envelope mirrored on `BootTiming` so
// callers can chain `emitFindServiceBoot` → `emitMethodRequestAfter` with
// the same wall-time vocabulary. `pre_emit_wait` is the gap *after* the
// last preceding stimulus (FindService) so the DUT has already published
// its OfferService before the Request arrives.
struct MethodRequestTiming {
    std::chrono::milliseconds pre_emit_wait{500};
    int total_emits{1};
    std::chrono::milliseconds retry_interval{200};
};

// High-level TESTER Method Request emit. Intended to follow an
// `emitFindServiceBoot` call — the latter blocks until the DUT's
// OfferService cycle is well underway, so the Request lands on a service
// that is already offered. Each emit binds an ephemeral UDP source port
// (kernel-picked) on `iface`, sends the SOME/IP Request to `dest`, and
// closes. session_id increments per emit (0x0001, 0x0002, ...).
//
// Blocks the calling thread for `pre_emit_wait + (total_emits - 1) *
// retry_interval`. Returns 0 on success or the first negative return on
// any failure; no retry-on-failure (cadence is fixed).
int emitMethodRequestAfter(std::string_view iface, const SomeIpRpcMessage &target,
                           const MethodRequestTiming &timing,
                           const MethodRequestDestination &dest);

// TCP variant of `emitMethodRequestAfter`. Used by §5.1.5.7 RPC_17 to
// drive multi-instance Method Request/Response over the reliable TCP
// endpoint (vsomeip's tcp_server_endpoint). Each emit opens a fresh
// SOCK_STREAM socket bound to an ephemeral source port on `iface`,
// connects to `dest`, sends the SOME/IP datagram, dwells `linger` so
// vsomeip has time to process and reply on the same socket, and
// closes. Distinct from the UDP variant because TCP requires the
// 3-way handshake before payload — keeps the post-send dwell so the
// kernel can deliver the Response to pcap before close() RSTs the
// connection.
struct MethodRequestTcpDwell {
    std::chrono::milliseconds linger{300};
};

int emitMethodRequestTcpAfter(std::string_view iface, const SomeIpRpcMessage &target,
                              const MethodRequestTiming &timing,
                              const MethodRequestDestination &dest,
                              const MethodRequestTcpDwell &dwell = {});

// §5.1.6 SOMEIP_ETS_037 helper. Variant of `emitMethodRequestTcpAfter`
// that sleeps `pre_emit_wait`, opens a SOCK_STREAM bound to an ephemeral
// source on `iface`, connects to `dest`, sends one Method Request built
// from `target`, dwells `dwell_after_send` (so the DUT can deliver its
// Response before the caller proceeds), and returns the connected fd
// WITHOUT closing it. Returns -1 on failure (any transient fd is closed
// before returning). Caller is responsible for `close()` either via
// `getTcpPeerStateAndClose` or directly.
//
// Used to keep the SOME/IP TCP reliable connection alive across a
// follow-up tester-injected resetInterface fire&forget over UDP, so
// tester-side `getsockopt(SOL_TCP, TCP_INFO).tcpi_state` can verdict
// whether the DUT honored the reset by emitting FIN
// (= TCP_CLOSE_WAIT on the tester's socket) or ignored it per spec
// (= TCP_ESTABLISHED).
int emitMethodRequestTcpAndHold(std::string_view iface, const SomeIpRpcMessage &target,
                                const MethodRequestDestination &dest,
                                std::chrono::milliseconds pre_emit_wait =
                                    std::chrono::milliseconds(500),
                                std::chrono::milliseconds dwell_after_send =
                                    std::chrono::milliseconds(1000));

// §5.1.6 SOMEIP_ETS_068/_069 helpers — pack multiple SOME/IP Method
// Requests into a single L4 datagram and emit it in one syscall. The
// spec body for both cases ("send three SOMEIP messages in one
// TCP/UDP package with one unaligned SOMEIP message") relies on the
// wire-level concatenation, so each target's bytes are built via
// `buildMethodRequest` and appended back-to-back; vsomeip's
// udp_server_endpoint / tcp_server_endpoint walks the buffer using
// the per-message Length header to dispatch each Request. Each
// emit binds an ephemeral source port on `iface`, sleeps
// `pre_emit_wait` first (mirroring `emitMethodRequestAfter`), and
// returns 0 on success or a negative on the first failure.
//
// `targets` order is the wire order; session_id stays as set in each
// target (no auto-increment — caller supplies distinct session_ids
// to keep the per-message Responses pinnable in a multi-phase
// SCXML).

int emitBundledMethodRequestsUdp(std::string_view iface,
                                 const std::vector<SomeIpRpcMessage> &targets,
                                 std::chrono::milliseconds pre_emit_wait,
                                 const MethodRequestDestination &dest);

int emitBundledMethodRequestsTcp(std::string_view iface,
                                 const std::vector<SomeIpRpcMessage> &targets,
                                 std::chrono::milliseconds pre_emit_wait,
                                 const MethodRequestDestination &dest,
                                 std::chrono::milliseconds linger =
                                     std::chrono::milliseconds(500));

// Reads `SOL_TCP / TCP_INFO` from `fd` (must be SOCK_STREAM) into
// `*out_tcpi_state` and unconditionally closes `fd`. tcpi_state values
// are from `<netinet/tcp.h>`: `TCP_ESTABLISHED=1`, `TCP_SYN_SENT=2`,
// `TCP_FIN_WAIT1=4`, `TCP_FIN_WAIT2=5`, `TCP_TIME_WAIT=6`, `TCP_CLOSE=7`,
// `TCP_CLOSE_WAIT=8`, ... Returns 0 on success, negative on getsockopt
// failure (in which case `*out_tcpi_state` stays 0 and `fd` is still
// closed). Used by §5.1.6 ETS_037 to verdict DUT-side FIN absence after
// a tester resetInterface stimulus.
int getTcpPeerStateAndClose(int fd, std::uint8_t *out_tcpi_state);

// §5.1.6 SOMEIP_ETS_097 helper — open a TCP listener bound to `iface`'s
// IPv4 + `port`. SO_REUSEADDR is set so successive cases on the same port
// skip TIME_WAIT recycling. Returns the listening fd on success (caller
// closes), or a negative errno-derived sentinel on failure. The "refusal"
// behaviour the spec demands is the absence of a listener — kernel emits
// RST on any SYN to a closed port, producing ECONNREFUSED on the DUT side
// without any active tester action. This helper is therefore only used to
// flip from refuse mode to accept mode partway through the stimulus chain.
int openTcpListener(std::string_view iface, std::uint16_t port);

// accept() with a poll-driven timeout. Returns 1 if an inbound connection
// was accepted (the accepted fd is immediately closed; ETS_097 only needs
// the wire-side handshake completion), 0 if the timeout elapsed without an
// accept, or a negative errno-derived sentinel on failure. The listener fd
// is left open so the caller can chain accept calls / close on its own
// timing.
int acceptTcpOnce(int listen_fd, std::chrono::milliseconds timeout);

}  // namespace tc8::stimulus
