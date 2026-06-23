#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// TC8 §4.8.5 Upper Tester wire protocol.
//
// The spec defines the Upper Tester as "another type of communication
// with the IUT that enables the tester to trigger some wished behaviors
// on the IUT; promting it to send certain types of messages, or to
// check its state and the received messages. This communication is
// carried out through a separate UDP port." (§4.8.5 p288).
//
// The spec leaves the wire format unspecified and points at AUTOSAR's
// Testability Protocol as an example. This header defines the minimal
// opcode surface the §4.4.4.5 / §4.4.4.6 cases (ADDRESSING_01/02, FRAGMENTS_05)
// need. A future §4.8 TCP session or §4.7 DHCP session can extend it
// by adding opcodes — additive, not edit, so the three landed cases
// never regress.
//
// ## Wire format
//
// All multi-byte integers are big-endian. Every frame is one UDP
// datagram addressed to `kPort` on the DUT (request) or the tester's
// ephemeral source port (response).
//
//   Request:   <opcode:u8> <req_id:u8> <params...>
//   Response:  <opcode | 0x80 :u8> <req_id:u8> <status:u8> <data...>
//
// The `req_id` field correlates a response with its request under
// concurrent-in-flight operation. Today every consumer sends one
// request and waits for one response, so the harness uses it
// monotonically. `status` is 0x00 on success; non-zero values are
// opcode-specific error codes (`kStatus*` below).
//
// Hex-space is disjoint from a UDP checksum byte so dissector code
// that peeks at `payload[0]` can cleanly split request vs response
// without re-parsing the surrounding UDP header.

namespace tc8::ut {

// Big-endian u16 reader for the wire format above — the single source for every
// producer/consumer of this protocol (the UT server core and its platform opcode
// extensions), mirroring testability_protocol.h::readU16. All multi-byte UT
// fields are big-endian (see "Wire format" above).
inline std::uint16_t readU16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

// tc8-dut UT server port. The spec only mandates a "separate UDP
// port" — the concrete value is a harness convention. Chosen outside
// the SOME/IP unicast range (30490..30510, see tc8::dut::kCapturePortHigh)
// and far from vsomeip defaults so accidental co-location cannot
// happen.
inline constexpr std::uint16_t kPort = 30600;

// Data port the DUT application layer binds to and that the tester
// sends UDP stimuli to for §4.4.4.5 ADDRESSING_01/02. Spec names this
// `<unusedUDPSrcPort>` (TC8 §4.4.4.6 FRAGMENTS_05 parameter, reused
// here for the co-located consumers). Single source of truth shared
// between tc8-dut's data-listener bind and the tester stimulus's
// destination port — keeping these in one header prevents silent
// drift if the value is ever retuned.
inline constexpr std::uint16_t kDataPort = 20000;

// Source port the tester uses when injecting stimuli addressed to
// `kDataPort`. Spec names this `<unusedUDPDstPort1>`. Also used as
// the DUT's source port when the UT `TriggerSendUdp` opcode fires
// (FRAGMENTS_05 spec fixes src=20001, dst=20000 on the DUT-emitted
// datagram).
inline constexpr std::uint16_t kDataPeerPort = 20001;

// Tester-side source port every harness-originated UT request rides
// on (raw-injected or socket-bound); the DUT's UT response returns to
// it. A single value across all spec areas lets pcap readers attribute
// "src=30600 / dst=30600" frames to the UT channel and BPF filters
// narrow on one port pair. Harness convention, not spec-mandated —
// historically this literal was scattered per-pilot (20100); keep new
// call sites on this constant.
inline constexpr std::uint16_t kTesterSrcPort = 20100;

// Upper-limit on a single request/response payload. §4.4 cases send
// 8 B Data regions; 256 B headroom covers future TCP test cases that
// want to trigger short segment exchanges without fragmentation. UDP
// packets staying <= 512 B avoid IPv4 fragmentation on standard MTU
// links, which matters for tests that observe emit-side fragment
// fields (e.g. FRAGMENTS_05).
inline constexpr std::uint16_t kMaxPayload = 256;

// Response bit — OR'd onto the request opcode to produce the
// response opcode. A receiver distinguishes "request for me" from
// "my own response" by testing bit 7.
inline constexpr std::uint8_t kResponseBit = 0x80;

enum Opcode : std::uint8_t {
    // Request / Response: "Did the DUT application layer receive a
    // UDP datagram on port <listen_port> whose original destination
    // IP matches <expected_dst_ip>?". The tc8-dut bins receive
    // events by (listen_port, original_dst_ip) and returns the last
    // matching receipt; absence-check consumers (ADDRESSING_02) pass
    // an `expected_dst_ip` they expect NOT to have been received and
    // succeed on `received==0`.
    //
    //   Request params:  <listen_port:u16> <expected_dst_ip:u32>
    //   Response params: <received:u8> [<src_ip:u32> <src_port:u16>
    //                     <payload_len:u16> <payload[]>]
    OpGetReceivedUdp = 0x01,

    // Request / Response: "Cause the DUT to emit a UDP datagram
    // from <src_port> to <dst_ip>:<dst_port> carrying <payload>,
    // optionally binding the transient socket to a caller-specified
    // source IP." The tc8-dut binds a transient UDP socket to
    // (src_ip_override OR iface_ip, src_port) and calls sendto; the
    // tester observes the emitted datagram via pcap. Used by
    // FRAGMENTS_05 (no src_ip override) so the "TESTER: Cause DUT to
    // send" procedure step is an explicit RPC rather than an inferred
    // side-effect, and by §4.6.5.5 UDP_USER_INTERFACE_07 (src_ip
    // override = `<DIface-0-IP>` alias) so the spec's caller-specified
    // Source IP axis is observably distinct from the primary-iface
    // default.
    //
    //   Request params:  <src_port:u16> <dst_ip:u32> <dst_port:u16>
    //                    <payload_len:u16> <payload[]>
    //                    [<src_ip_be:u32>]   // optional, append-only
    //   Response params: (none beyond the status byte)
    //
    // Wire size: 12 + payload_len (legacy) OR 12 + payload_len + 4
    // (with override). The trailer is append-only — legacy callers
    // omit it and tc8-dut defaults the source binding to the primary
    // iface IP (`iface_ip_be_`), preserving FRAGMENTS_05 / UI_01..06
    // behaviour byte-for-byte. A non-zero `src_ip_be` instructs the
    // bind to that address; the address MUST be locally configured
    // (via netns alias `ip addr add`) or the bind syscall fails and
    // the call collapses to kStatusSendFailed. Override == 0 is
    // semantically equivalent to omitting the trailer (defensive
    // parity for callers that thread the field unconditionally).
    OpTriggerSendUdp = 0x02,

    // §4.8.5 spec procedure `<openTCPSocket(typeOfSocket=…)>`.
    // The leading `type` byte selects between passive and active open;
    // both flavours share the same opcode so a future stimulus dispatcher
    // can route on opcode alone and consult `type` only when deciding
    // socket semantics:
    //
    //   * type=kSocketTypePassive (0): the tc8-dut creates a SOCK_STREAM,
    //     SO_REUSEADDR, binds INADDR_ANY:<local_port>, listens, and
    //     spawns a one-shot acceptor thread. Used by BASICS_01..03 to
    //     observe DUT-side responses on the kernel-completed handshake.
    //   * type=kSocketTypeActive (1): the tc8-dut creates a SOCK_STREAM,
    //     binds (iface_ip, <local_port>) so the source address is
    //     deterministic for tester filtering, and calls connect() to
    //     <remote_ip>:<remote_port>. The same socket fd is stored as
    //     `accepted_fd` so OpQueryTcpEstablished's TCP_INFO read works
    //     unchanged. Used by BASICS_06+ where the DUT initiates the SYN
    //     under tester direction.
    //
    // After accept (passive) or connect (active) succeeds the listener
    // stores the connected fd; OpQueryTcpEstablished reads the kernel's
    // TCP state from that fd via `getsockopt(SOL_TCP, TCP_INFO)` for any
    // FSM-state assertion (BASICS_02 / BASICS_07).
    //
    //   Request params:  <type:u8> <local_port:u16>
    //                    [<remote_ip:u32> <remote_port:u16>]   // type=1 only
    //   Response params: <socket_id:u8>
    //
    // The remote endpoint trailer is omitted on passive opens — the
    // tc8-dut parser keys off `type` and ignores the trailing bytes.
    // Wire size: 4 B (passive) or 10 B (active) excluding opcode/req_id.
    //
    // Status codes: kStatusOk on success, kStatusBindFailed if bind /
    // listen fails (passive), kStatusConnectFailed if connect() fails
    // (active), kStatusMalformed if the active trailer is missing.
    OpOpenTcpSocket = 0x03,

    // Close a previously-opened TCP socket. Joins the acceptor thread
    // (which exits within 200 ms) and closes both listen_fd and any
    // accepted_fd. Idempotent on an unknown socket_id (returns
    // kStatusUnknownSocket without side effects).
    //
    //   Request params:  <socket_id:u8>
    //   Response params: (none beyond the status byte)
    OpCloseTcpSocket = 0x04,

    // Query whether a passive socket has reached the [established]
    // state. The tc8-dut reads the kernel's TCP FSM state off the
    // accepted fd via `getsockopt(SOL_TCP, TCP_INFO)` and answers 1
    // iff `tcpi_state == TCP_ESTABLISHED`. If accept() has not yet
    // returned an accepted fd the answer is 0 (the listener is in
    // LISTEN, not ESTABLISHED). §4.8.6.1 BASICS_02 reads this to
    // verify spec-literal "DUT moves on to ESTABLISHED state" — no
    // surrogate flag, the kernel's view of the FSM is the only source
    // of truth.
    //
    //   Request params:  <socket_id:u8>
    //   Response params: <established:u8>  (0 = no, 1 = yes)
    OpQueryTcpEstablished = 0x05,

    // §4.8.6.2 TCP_CHECKSUM_03 spec procedure step 2: "Cause the
    // application on the DUT-side to issue a SEND request for a data
    // segment". The tc8-dut writes `payload` bytes to the connected
    // fd via `::send()`; Linux's TCP stack frames the bytes into one
    // or more outbound segments whose checksum the tester then
    // verifies against the RFC 793 §3.1 pseudo-header rule. Used only
    // on a socket already in ESTABLISHED — a non-established socket's
    // ::send() returns ENOTCONN, which collapses to kStatusSendFailed.
    //
    //   Request params:  <socket_id:u8> <payload_len:u16> <payload[]>
    //   Response params: (none beyond the status byte)
    //
    // Wire size: 1 + 1 + 1 + 2 + payload_len. payload_len follows the
    // TriggerSendUdp convention: caller-side builders clamp at
    // kMaxPayload, parser rejects short frames as kStatusMalformed.
    OpSendTcpData = 0x06,

    // §4.8.6.8 TCP_CLOSING_07/_08 spec procedure step "Cause DUT side
    // application to issue a RECEIVE call". The tc8-dut blocks in
    // ::recv() on the socket's connected fd, accumulating bytes into a
    // buffer until either `expected_len` bytes have been read or
    // `timeout_ms` has elapsed. The collected bytes are returned in
    // the response body so the tester can verify the data matches what
    // it sent. Used on a socket that has at least reached ESTABLISHED
    // — Linux's TCP stack queues incoming data in any state where
    // tcp_data_queue runs (EST / FIN-WAIT-1 / FIN-WAIT-2 / CW), so the
    // recv() returns whatever the kernel has accepted regardless of
    // FSM state.
    //
    //   Request params:  <socket_id:u8> <expected_len:u16> <timeout_ms:u16>
    //   Response params: <received_len:u16> <bytes[]>
    //
    // Wire size: 1 + 1 + 1 + 2 + 2 = 7 bytes (request) /
    //            3 + 2 + received_len (response).
    //
    // The tc8-dut blocks the UT RPC server thread for up to
    // `timeout_ms`; per-worker case execution is serial so this does
    // not stall a concurrent test. `expected_len` is clamped at
    // kMaxPayload by the builder; received_len in the response can
    // be 0 (timeout with no data) up to the clamped expected_len.
    //
    // Status codes: kStatusOk on any non-fatal outcome (including
    // timeout with partial / zero bytes — caller verifies received_len
    // matches the expected count); kStatusUnknownSocket for an
    // unknown socket_id; kStatusMalformed for a short request.
    OpReceiveTcpData = 0x07,

    // §4.8.6.8 TCP_CLOSING_07/_08 spec procedure step "Cause DUT side
    // application to issue a CLOSE call" combined with the explicit
    // "Support of ETM Service Primitive SHUTDOWN" prerequisite (p351
    // / p352). The tc8-dut calls ::shutdown(fd, SHUT_WR) on the
    // accepted_fd: kernel emits FIN, socket transitions EST→FW1, but
    // the read direction remains open so a subsequent
    // OpReceiveTcpData can drain bytes that arrived in FW1/FW2.
    //
    // Distinct from OpCloseTcpSocket which calls ::close() — Linux's
    // tcp_close path RSTs on data arriving post-close (the kernel
    // assumes user-space can no longer consume), which would break
    // the spec assertion "DUT remains in FW1 / FW2".
    //
    //   Request params:  <socket_id:u8>
    //   Response params: (none beyond the status byte)
    OpShutdownTcpSocketWr = 0x08,

    // §4.8.6.5 TCP_CALL_ABORT_02/_03 spec procedure step "Cause the
    // application to issue an ABORT call". Linux exposes ABORT
    // semantics as `setsockopt(SO_LINGER, {l_onoff=1, l_linger=0})`
    // immediately followed by `::close()` — the kernel emits an RST
    // (instead of FIN) on the connection and disposes the socket
    // synchronously per `socket(7)` LINGER semantics. The tc8-dut
    // applies the option, calls close, and erases the socket_id
    // from the listener map so a subsequent OpQueryTcpEstablished /
    // OpReceiveTcpData on the same id returns kStatusUnknownSocket.
    //
    //   Request params:  <socket_id:u8>
    //   Response params: (none beyond the status byte)
    //
    // Wire size: 1 + 1 + 1 = 3 bytes.
    //
    // Distinct from OpCloseTcpSocket: that opcode follows the kernel's
    // graceful-close path (FIN egress, FW1/FW2 transitions). ABORT is
    // the spec primitive for "send RST and drop the connection now",
    // which is what TCP_CALL_ABORT_02/_03 require to verify the DUT's
    // CLOSED transition from EST / CLOSING / LAST-ACK / TIME-WAIT.
    OpAbortTcpSocket = 0x09,

    // §4.8.6.9 TCP_MSS_OPTIONS_06/_09/_10 spec procedure step "Cause
    // application to issue a SEND request for data with size at least
    // max(MSS)". The tc8-dut allocates a `total_len`-byte buffer
    // filled with `pattern` and writes it via ::send() — Linux
    // segments the payload according to the connection's negotiated
    // send MSS, and the tester observes the first DUT-emitted data
    // segment to verify its payload_len equals min(advertised, DUT_MSS).
    //
    // Distinct from OpSendTcpData: that opcode caps payload at
    // kMaxPayload=256 because the bytes traverse the UT UDP request
    // and a larger payload would either exceed MTU or fragment. MSS
    // verification needs >= 1500 B of data so the DUT's clamp to its
    // own MSS (1460 on 1500 B MTU) is observable, which only works
    // if the bulk-data generation lives tc8-dut-side.
    //
    //   Request params:  <socket_id:u8> <pattern:u8> <total_len:u16>
    //   Response params: (none beyond the status byte)
    //
    // Wire size: 1 + 1 + 1 + 1 + 2 = 6 bytes.
    //
    // Status codes: kStatusOk on success; kStatusUnknownSocket for an
    // unknown id; kStatusSendFailed if ::send() refused (ENOTCONN,
    // EPIPE, etc.); kStatusMalformed for a short request.
    OpSendTcpDataPattern = 0x0A,

    // §4.8.6.14 TCP_URGENT_PTR_04 spec procedure step "Cause the
    // application on the DUT-side to issue a RECEIVE call". The
    // tc8-dut blocks in `::recv(fd, buf, expected_len, MSG_OOB)`
    // up to `timeout_ms`, returning whatever urgent bytes Linux
    // delivered through the out-of-band path. Default Linux
    // behaviour (SO_OOBINLINE off, sysctl_tcp_stdurg=0) places one
    // urgent byte at `urg_seq` in the OOB queue; recv(MSG_OOB)
    // returns exactly that single byte. The spec assertion "DUT
    // returns the RECEIVE call putting only the urgent data" is
    // satisfied iff the response carries one byte equal to the
    // expected urgent byte.
    //
    //   Request params:  <socket_id:u8> <expected_len:u16> <timeout_ms:u16>
    //   Response params: <received_len:u16> <bytes[]>
    //
    // Wire size: 1 + 1 + 1 + 2 + 2 = 7 bytes (request) /
    //            3 + 2 + received_len (response).
    //
    // Distinct from OpReceiveTcpData (0x07): same params/response
    // shape, but the tc8-dut backend passes `MSG_OOB` to recv()
    // so urgent and non-urgent data sit in independent buffers
    // per RFC 793 §3.7 Urgent Pointer interface semantics.
    //
    // Status codes: kStatusOk on any non-fatal outcome (including
    // recv timeout / EAGAIN with no urgent data — caller verifies
    // received_len == 1 and the byte content);
    // kStatusUnknownSocket for an unknown socket_id;
    // kStatusMalformed for a short request.
    OpReceiveTcpDataOob = 0x0B,

    // §4.5 IPv4 Link-Local Autoconfiguration (RFC 3927) start trigger.
    // Every §4.5 case body opens with the precondition pair
    //   "DUT CONFIGURE: Externally configure DHCP Client + bring up
    //    iface" → "DUT: Sends DHCPDISCOVER" → ... → DUT begins LL
    // probing.
    // The tc8-dut owns no real DHCP client; this opcode collapses the
    // precondition into one RPC: emit a single observable DHCPDISCOVER
    // frame, sleep <dhcp_timeout_ms> to model "no DHCP server replied",
    // then start the RFC 3927 PROBE/ANNOUNCE state machine on a
    // randomly-chosen 169.254.X.Y address (X in [1, 254]).
    //
    // Timing knobs are exposed so per-case SCXML deadlines can stay
    // compact: the spec defaults (PROBE_WAIT 1-2 s, ANNOUNCE_WAIT 2 s)
    // sum to ~10 s wall, but most §4.5 observation cases only need to
    // see the FIRST Probe or the FIRST Announce. Pass shorter values
    // (200-400 ms range) for those; pass spec defaults for the
    // §4.5.6.2 ADDRESS_SELECTION_09/_10 timing-shape cases that
    // verify the cadence itself.
    //
    //   Request params:
    //     <dhcp_timeout_ms:u16>     <probe_wait_ms:u16>
    //     <probe_min_ms:u16>        <probe_max_ms:u16>
    //     <announce_wait_ms:u16>    <announce_interval_ms:u16>
    //     <rate_limit_interval_ms:u16>
    //   Response params: (none beyond the status byte)
    //
    // Wire size: 1 + 1 + 14 = 16 bytes (request) /
    //            1 + 1 + 1 = 3 bytes (response).
    //
    // RFC 3927 §2.2.1 RATE_LIMIT_INTERVAL — the silence window the
    // host enforces after MAX_CONFLICTS=10 conflicts. Spec default
    // 60 000 ms; harness fast envelope uses 3 000 ms so §4.5.6.2 _14
    // SCXML deadline (12 s) accommodates 10 conflict cycles + one
    // full silence window without bumping the wall budget. _11/_12/_13
    // pass any value (they finish well before the 10th conflict).
    //
    // Idempotency: a second OpStartLLAutoconf while a state machine is
    // already running aborts the previous machine before starting the
    // new one. This keeps the harness's "fresh per case" guarantee
    // even if a prior case crashed mid-sequence.
    //
    // Status codes: kStatusOk on success; kStatusMalformed for a short
    // request.
    OpStartLLAutoconf = 0x0C,

    // §4.5 IPv4 Link-Local Autoconfiguration query. Returns the LL
    // address the tc8-dut chose at PROBE selection time, in network
    // byte order. Returns 0.0.0.0 (all zeros) if the state machine
    // has not yet committed an address (still in PROBE phase, or no
    // OpStartLLAutoconf has been issued). §4.5 cases that observe
    // post-Probe ARP traffic (ANNOUNCING_*, NETWORK_PARTITIONS_01)
    // call this after a deterministic wait so SCXML guards can pin
    // `captured.target_proto_ip == ut.linklocal_addr`.
    //
    //   Request params:  (none)
    //   Response params: <linklocal_addr:u32 BE>
    //
    // Wire size: 1 + 1 = 2 bytes (request) /
    //            1 + 1 + 1 + 4 = 7 bytes (response).
    OpQueryLLAddress = 0x0D,

    // §4.5 IPv4 Link-Local Autoconfiguration abort. Stops the running
    // state-machine thread and releases the chosen LL address. Used
    // by case CLEANUP to guarantee one case's leftover LL state does
    // not leak into the next case's Probe selection (which would
    // otherwise race the random pick).
    //
    //   Request params:  (none)
    //   Response params: (none beyond the status byte)
    //
    // Wire size: 1 + 1 = 2 bytes.
    //
    // Idempotent on a state machine that is already stopped (returns
    // kStatusOk).
    OpAbortLLAutoconf = 0x0E,

    // §4.5 fault-injection variant of OpStartLLAutoconf for the
    // self-reference-trap mitigation. Same six timing knobs as 0x0C
    // followed by a single `flavor` byte that tells tc8-dut to
    // deliberately mutate one ARP frame field per RFC 3927 §2.1 /
    // RFC 3927 §2.1.1 / RFC 3927 §2.2.1 / RFC 3927 §2.4 invariant. Drives the negative-path
    // verification of §4.5.6.2 ADDRESS_SELECTION cluster A and
    // §4.5.6.3 ANNOUNCING SCXML fail_state branches that conformant
    // emit can never trigger — without this opcode, those branches
    // are dead code and the harness silently accepts a buggy DUT.
    //
    // The mutation is uniform across every spec-mandated emission of
    // the affected phase — Probe-shape flavors mutate all three
    // Probes; Announce-shape flavors mutate both Announces. A one-shot
    // mutation would race the SCXML's first-frame-only filter. Frames
    // outside the flavor's phase stay compliant (e.g. an Announce
    // flavor leaves Probes unchanged), so the spec-precondition
    // sequence still completes and the SCXML reaches the listening
    // state for its phase.
    //
    //   Request params:
    //     <dhcp_timeout_ms:u16>     <probe_wait_ms:u16>
    //     <probe_min_ms:u16>        <probe_max_ms:u16>
    //     <announce_wait_ms:u16>    <announce_interval_ms:u16>
    //     <rate_limit_interval_ms:u16>
    //     <flavor:u8>
    //   Response params: (none beyond the status byte)
    //
    // Wire size: 1 + 1 + 14 + 1 = 17 bytes (request) /
    //            1 + 1 + 1 = 3 bytes (response).
    //
    // Same seven u16 timing knobs as 0x0C in the same byte order, plus
    // the trailing flavor byte. The parity matters because the negative
    // cluster's helpers thread the same `Params` struct as the positive
    // cluster — a wire-shape divergence between 0x0C and 0x0F would
    // force the harness to maintain two parameter paths.
    // `rate_limit_interval_ms` has no observable effect on the negative
    // cases (they finish in one PROBE attempt, never reach
    // MAX_CONFLICTS); the helper passes
    // `tc8::rfc3927::kRateLimitIntervalMs` and tc8-dut's
    // `LinklocalAutoconf` ignores it on the conformant path.
    //
    // Flavor byte values (kFlavor*): see below. Unknown values fall
    // through to compliant emit (None) so a future opcode revision
    // adding a new flavor doesn't break older callers — the harness
    // self-validation surfaces the missing branch as a fail_compliant
    // verdict on the relevant negative case.
    //
    // Idempotency / status codes mirror OpStartLLAutoconf.
    OpStartLLAutoconfBuggy = 0x0F,

    // §4.7 DHCPv4 client lifecycle start trigger. The tc8-dut owns a
    // mini state machine (DHCPDISCOVER → wait OFFER → DHCPREQUEST →
    // wait ACK → BOUND) that satisfies the §4.7.6.1 SUMMARY_01 spec
    // procedure step pair "DUT: Sends DHCPDISCOVER" / "DUT: Sends
    // DHCPREQUEST" against a tester-side server emul.
    //
    // Distinct from `OpStartLLAutoconf` (0x0C) which fires a one-shot
    // DHCPDISCOVER then falls back to RFC 3927 LL probing on no
    // server reply. The §4.7 lifecycle path:
    //   * persists xid across DISCOVER → REQUEST (RFC 2131 §4.3.2)
    //   * captures yiaddr + server_identifier from the OFFER and
    //     echoes them into the REQUEST (Option 50 + 54)
    //   * stays in BOUND until OpAbortDhcpClient or process exit
    //   * has no LL fallback — failed OFFER / ACK ends in a Failed
    //     state observable via OpQueryDhcpLease returning 0
    //
    //   Request params:
    //     <offer_wait_ms:u16>    <ack_wait_ms:u16>
    //     <retry_count:u8>       <retry_interval_ms:u16>
    //     [<nak_to_discover_min_ms:u16>     <nak_to_discover_max_ms:u16>]
    //     [<arp_probe_listen_ms:u16>]
    //     [<decline_to_discover_min_ms:u16> <decline_to_discover_max_ms:u16>]
    //     [<retx_first_ms:u16>              <retx_cap_ms:u16>
    //      <retx_jitter_ms:u16>]
    //     [<iface_index:u8>]
    //     [<flavor:u8>]
    //   Response params: (none beyond the status byte)
    //
    // Wire size grows 9 → 13 → 15 → 19 → 25 → 26 → 27 bytes across
    // S2..S6b/S9/S10/S12/S13 + Phase F. Legacy callers default every later
    // slot to 0, preserving instant-restart, skip-Probe,
    // instant-restart-after-DECLINE, flat-retry, primary-iface (index=0),
    // and compliant (kDhcpFlavorNone) behaviour.
    //
    // The trailing `flavor` byte (param offset 24, present only at >= 25
    // param bytes) is fault-injection-only: it selects a deliberately
    // non-conformant Dhcpv4Client code path for the §4.5.6.1 / §4.7
    // negative cases. Positive cases omit it; the handler defaults to
    // kDhcpFlavorNone so their wire shape and behaviour are unchanged.
    // See kDhcpFlavor* below.
    //
    // §4.7.6.5 USAGE_01 / RFC 2131 §3.6 MUST: a client with multiple
    // network interfaces uses DHCP through each interface independently.
    // tc8-dut enumerates non-loopback up AF_INET ifaces at start() and
    // creates one `Dhcpv4Client` per iface, sorted by name (lexicographic
    // → primary = veth-dut-W, secondary = veth-dut2-W). `iface_index`
    // selects which instance receives the OpStartDhcpClient call. Out-of-
    // range index returns kStatusMalformed (no silent fallback to 0 — a
    // wrong-index call is a tester-side bug, not a transport mismatch).
    //
    // Idempotency: a second OpStartDhcpClient on the SAME iface_index
    // while that instance's state machine is already running aborts the
    // previous one before starting fresh, matching the OpStartLLAutoconf
    // convention. Per-iface idempotency: starting iface_index=1 does
    // NOT abort iface_index=0's running machine.
    //
    // Status codes: kStatusOk on success; kStatusMalformed for a short
    // request OR an iface_index outside the registered range.
    OpStartDhcpClient = 0x10,

    // §4.7 DHCPv4 client lease query. Returns the bound IPv4 address
    // (yiaddr from the matched ACK) in network byte order, or
    // 0.0.0.0 if the state machine has not yet reached BOUND. Used by
    // §4.5.6.1 IPv4_AUTOCONF_INTRO_01 to confirm the DUT acquired a
    // routable address (and therefore SHOULD NOT fall back to LL),
    // and by future §4.7 reacquisition cases.
    //
    //   Request params:  (none)
    //   Response params: <lease_be:u32 BE>
    //
    // Wire size: 1 + 1 = 2 bytes (request) /
    //            1 + 1 + 1 + 4 = 7 bytes (response).
    OpQueryDhcpLease = 0x11,

    // §4.7 DHCPv4 client abort. Stops the running state-machine
    // thread and clears the bound lease.
    //
    //   Request params:  (none)
    //   Response params: (none beyond the status byte)
    //
    // Wire size: 1 + 1 = 2 bytes.
    //
    // Idempotent on a state machine that is already stopped (returns
    // kStatusOk).
    OpAbortDhcpClient = 0x12,

    // §4.8.6.11 TCP_RETRANSMISSION_TO kernel-side observation. The
    // tc8-dut reads `struct tcp_info` off the connected fd via
    // `getsockopt(SOL_TCP, TCP_INFO)` and returns four fields the
    // tester needs to verdict RFC 6298 RTO behaviour without depending
    // on pcap timing of retransmits:
    //
    //   * tcpi_state        — Linux TCP FSM state (1=ESTABLISHED, ...).
    //   * tcpi_rto          — current retransmission timeout in
    //                          microseconds. Doubled by `tcp_retransmit_
    //                          timer`'s out_reset_timer on every retx
    //                          (RFC 6298 §5.5); preserved across Karn-
    //                          excluded ACKs (RFC 6298 §3 / §5.3) so
    //                          the test can verify Karn's algorithm by
    //                          reading `rto` after the ACK and seeing
    //                          the doubled value persist.
    //   * tcpi_retransmits  — count of retransmits the kernel has fired
    //                          on this socket since connection start
    //                          (`icsk_retransmits`). Non-zero proves
    //                          retx fired without depending on pcap
    //                          delivering the duplicate frame within a
    //                          tight wall-clock window.
    //   * tcpi_unacked      — number of segments outstanding (`tp->
    //                          packets_out`). Zero ⇒ all sent data
    //                          ACK'd; non-zero ⇒ retransmit timer is
    //                          armed for the unacked range.
    //
    // Distinct from OpQueryTcpEstablished (0x05) which returns one
    // boolean: the §4.8.6.11 cluster needs RTO doubling + retransmit
    // count, not just FSM state. A new opcode preserves the existing
    // BASICS_02 wire shape (`<established:u8>` 1-byte response) so no
    // legacy consumer is broken.
    //
    //   Request params:  <socket_id:u8>
    //   Response params: <state:u8> <rto_us:u32 BE> <retransmits:u8>
    //                    <unacked:u32 BE>
    //
    // Wire size: 1 + 1 + 1 = 3 bytes (request) /
    //            1 + 1 + 1 + 1 + 4 + 1 + 4 = 13 bytes (response).
    //
    // Status codes: kStatusOk on a successful TCP_INFO read;
    // kStatusUnknownSocket if `socket_id` is not in the active map;
    // kStatusMalformed for a short request. A getsockopt failure
    // collapses to kStatusUnknownSocket — same outcome as if the
    // listener never existed — keeping the surface tristate (ok /
    // unknown / malformed) for caller-side parsing.
    OpQueryTcpInfo = 0x13,

    // §4.6.5.5 UDP_USER_INTERFACE_01 spec procedure step "DUT: Create
    // 10 receive ports on <DIface-0>". The tc8-dut binds `count` UDP
    // SOCK_DGRAM sockets to (INADDR_ANY, ephemeral port=0); the kernel
    // assigns each a distinct ephemeral port. The created fds are held
    // open for the rest of the tc8-dut process lifetime so the spec's
    // "Verify using Upper Tester that DUT has created N receive ports"
    // is observable as `actual_count == count`. Closed in `stop()`.
    //
    //   Request params:  <count:u8>
    //   Response params: <actual_count:u8>
    //
    // Wire size: 1 + 1 + 1 = 3 bytes (request) /
    //            1 + 1 + 1 + 1 = 4 bytes (response).
    //
    // Idempotency: a second OpCreateUdpReceivePorts call appends to the
    // existing fd list; if more sockets are needed the additive shape
    // keeps prior receive-port state intact for any cross-case
    // observation. tc8-dut's `stop()` closes every fd in the list.
    //
    // Status codes: kStatusOk on success (actual_count may be < count
    // if the kernel ran out of ephemeral ports — the SCXML pass guard
    // verdicts on the count match, not on the status byte alone);
    // kStatusMalformed for a short request.
    OpCreateUdpReceivePorts = 0x14,

    // Side-effect-free liveness + capability probe. The DUT answers
    // with the highest opcode value its UT implementation handles, so
    // a tester can (a) verify UT reachability before running any case
    // — smoke-test.sh topology preflights use this against external /
    // remote DUTs — and (b) detect the feature level of a DUT firmware
    // that implements only an opcode subset. The handler reads no
    // state and mutates none: safe to fire against a DUT mid-test,
    // repeatedly, from any topology.
    //
    // `max_opcode` is the top of the implementation's CONTIGUOUS
    // 0x01..N block — a sparse implementation answers the highest N
    // with no gap below it (the lwIP DUT reports 0x0B although it
    // also handles the 0x13+ block). The exact implemented set is
    // OpQueryCapabilities (0x16)'s bitmap; this byte stays the
    // coarse liveness-probe feature level for one-frame consumers.
    //
    //   Request params:  (none)
    //   Response params: <max_opcode:u8>
    //
    // Wire size: 1 + 1 = 2 bytes (request) /
    //            1 + 1 + 1 + 1 = 4 bytes (response).
    //
    // Status codes: kStatusOk always — a malformed (short) frame
    // cannot exist for a parameterless request beyond the 2-byte
    // header the dispatcher already requires.
    OpPing = 0x15,

    // Precise implemented-opcode surface query. OpPing's single
    // `max_opcode` byte presumes a contiguous implementation
    // 0x01..max — an assumption the lwIP DUT already breaks (it
    // implements 0x01..0x0B plus the 0x13+ block, and its honest
    // OpPing answer 0x0B hides the upper block entirely). The
    // response is a length-prefixed bitmap over the opcode value
    // space: bit (opcode % 8) of byte (opcode / 8), set = the DUT's
    // dispatcher handles that opcode. Bit 0 (opcode 0x00 does not
    // exist) is never set. Length-prefixed so future opcode
    // additions extend the bitmap additively — older callers read
    // the bytes they know, newer callers see zero-padding semantics
    // for bytes a shorter response omits.
    //
    // Side-effect-free like OpPing: reads a process-lifetime constant,
    // mutates nothing, safe from any topology at any time. A pre-0x16
    // DUT answers kStatusUnknownOpcode — callers degrade to the
    // OpPing feature-level byte.
    //
    //   Request params:  (none)
    //   Response params: <bitmap_len:u8> <bitmap[bitmap_len]>
    //
    // Wire size: 1 + 1 = 2 bytes (request) /
    //            3 + 1 + bitmap_len bytes (response).
    //
    // Status codes: kStatusOk always (parameterless, like OpPing).
    OpQueryCapabilities = 0x16,

    // TC8 §4.2.4.2 ARP_48/49 "DUT CONFIGURE" cache-conditioning steps,
    // rendered as a UT RPC for DUT stacks whose ARP-cache lifecycle
    // the tester cannot reach from outside the wire. The spec's own
    // procedure conditions the DUT cache explicitly — ARP_48 step 1
    // "clear the dynamic entries in the ARP Cache", step 2 "set a
    // timeout of <DYNAMIC-ARP-CACHE-TIMEOUT> seconds", step 8 "wait
    // <DYNAMIC-ARP-CACHE-TIMEOUT> + <ARP-TOLERANCE-TIME> for the ARP
    // cache to get refreshed". The Linux reference DUT renders those
    // steps externally (smoke-test.sh per-case netns sysctls compress
    // base_reachable_time_ms / delay_first_probe_time) and therefore
    // does NOT implement this opcode; the lwIP DUT ages its table at
    // a compile-time ARP_MAXAGE no external knob can move, so the
    // conditioning has to ride the UT channel into the stack itself.
    //
    //   Request params:  <action:u8> <param:u16>
    //   Response params: (none beyond the status byte)
    //
    // Wire size: 1 + 1 + 1 + 2 = 5 bytes (request) /
    //            1 + 1 + 1 = 3 bytes (response).
    //
    // Actions (kArpCondition*): see below. The u16 `param` is
    // action-specific (seconds for AgeBySeconds, ignored for
    // FlushAll). An unknown action byte answers kStatusMalformed —
    // unlike the 0x0F flavor byte there is no compliant fallback
    // semantics for a conditioning the DUT does not recognise, and a
    // silent no-op would let the case run against an unconditioned
    // cache and time out with a misleading verdict.
    //
    // Status codes: kStatusOk on success; kStatusMalformed for a
    // short request or an unknown action byte.
    OpConditionArpCache = 0x17,

    // Arm an EGRESS field-fault flavor (kEgressFault* / k*Fault* catalog below) on
    // the lwIP fixture. lwIP-specific, like OpConditionArpCache: the kernel-backed
    // tc8-dut faults nothing here (no fixture seam), so the matching `_neg` cases
    // capability-skip on Linux. While a non-None flavor is set, the fixture's netif
    // link-output corrupts one header field of the DUT-emitted frame — the lwIP
    // analog of a tc8-dut emit-flavor, generic over protocol (ARP + UDP today;
    // TCP/IPv4/ICMP add a dispatch branch on the same catalog). The resulting
    // checksum mismatch is immaterial — each guard reads the mutated field.
    //
    // Params: <flavor:u8>. Status: kStatusOk; kStatusMalformed for a short request
    // or an unknown flavor byte.
    OpSetEgressFlavor = 0x18,

    // Arm an INGRESS prohibited-emission flavor (kIngressFault* catalog below) on
    // the lwIP fixture: the netif input hook makes a buggy DUT produce the emission
    // a §4.2.4.2 reception case proves absent (synthesize the forbidden ARP Reply,
    // or wrongly learn the dropped frame's address). A separate mechanism from
    // egress field-corruption (different hook point), hence its own opcode + cap.
    //
    // Params: <flavor:u8>. Status: kStatusOk; kStatusMalformed for a short request
    // or an unknown flavor byte.
    OpSetIngressFlavor = 0x19,

    // Arm an APP-LAYER reception-fault flavor (kAppFault* catalog below) on the lwIP
    // fixture. The §4.4.4.5 directed-broadcast destination-address discard is an
    // application decision per RFC 1122 — the IP stack delivers the datagram to the
    // data listener, which then drops it on the RECVINFO-recovered destination address
    // (UpperTesterServer::dataListenerLoop). A non-None flavor makes that listener skip
    // its discard so a buggy DUT counts the
    // datagram it must drop — a SEPARATE seam from the egress/ingress wire faults (the
    // drop is post-delivery, in the shared data listener, not a frame mutation), hence
    // its own opcode + cap. lwIP-only like the other fault opcodes: the kernel-backed
    // tc8-dut never registers it, so the matching `_neg` capability-skips on Linux.
    //
    // Params: <flavor:u8>. Status: kStatusOk; kStatusMalformed for a short request
    // or an unknown flavor byte.
    OpSetAppFlavor = 0x1A,
};

// Top of the protocol's opcode value space — the highest opcode this
// header defines. Bump alongside every opcode addition; the adjacency
// to the enum keeps the two from drifting. Per-implementation maxima
// live with each DUT server (the reference tc8-dut and the lwIP DUT
// each answer OpPing with their own honest contiguous top, and
// OpQueryCapabilities with their exact implemented set — the
// reference DUT itself skips OpConditionArpCache, whose §4.2 cache
// conditioning rides netns sysctls instead).
inline constexpr std::uint8_t kMaxProtocolOpcode = OpSetAppFlavor;

// Wire encoding of the OpQueryTcpInfo `state` byte — the single source
// of truth for every producer and consumer. Values equal the Linux
// kernel's TCP FSM numbering (<netinet/tcp.h>) because the Linux
// tc8-dut passes `tcpi_state` through verbatim; it static_asserts the
// equivalence at the pass-through site, and non-Linux DUTs translate
// their stack's own state enum to these constants (e.g. lwIP's
// tcpbase.h numbers the same FSM differently —
// dut/lwip_dut/lwip_stack_probe.cpp wireTcpState). Frozen wire ABI:
// SCXML conds pin these values numerically and cannot include this
// header, so the numbers must never change.
inline constexpr std::uint8_t kTcpStateEstablished = 1;
inline constexpr std::uint8_t kTcpStateSynSent     = 2;
inline constexpr std::uint8_t kTcpStateSynRecv     = 3;
inline constexpr std::uint8_t kTcpStateFinWait1    = 4;
inline constexpr std::uint8_t kTcpStateFinWait2    = 5;
inline constexpr std::uint8_t kTcpStateTimeWait    = 6;
inline constexpr std::uint8_t kTcpStateClose       = 7;
inline constexpr std::uint8_t kTcpStateCloseWait   = 8;
inline constexpr std::uint8_t kTcpStateLastAck     = 9;
inline constexpr std::uint8_t kTcpStateListen      = 10;
inline constexpr std::uint8_t kTcpStateClosing     = 11;

// Response status byte.
inline constexpr std::uint8_t kStatusOk              = 0x00;
inline constexpr std::uint8_t kStatusMalformed       = 0x01;  // short frame / bad len
inline constexpr std::uint8_t kStatusUnknownOpcode   = 0x02;
inline constexpr std::uint8_t kStatusSendFailed      = 0x03;  // TriggerSendUdp / OpSendTcpData socket/send error
inline constexpr std::uint8_t kStatusBindFailed      = 0x04;  // OpOpenTcpSocket(Passive) bind/listen error
inline constexpr std::uint8_t kStatusUnknownSocket   = 0x05;  // socket_id not in active map
inline constexpr std::uint8_t kStatusConnectFailed   = 0x06;  // OpOpenTcpSocket(Active) connect() error

// `OpOpenTcpSocket` `type` byte. Passive=listen for an incoming
// handshake (DUT observes tester-driven SYN); Active=initiate the
// handshake (DUT emits its own SYN to <remote_ip>:<remote_port>).
inline constexpr std::uint8_t kSocketTypePassive = 0x00;
inline constexpr std::uint8_t kSocketTypeActive  = 0x01;

// `OpStartLLAutoconfBuggy` flavor byte. Each value picks one of the
// RFC 3927 invariants asserted by §4.5.6.2 ADDRESS_SELECTION cluster A
// (Probe-shape, 0x01..0x05 + 0x0A), §4.5.6.3 ANNOUNCING (Announce-shape,
// 0x06..0x09), defending-Reply-shape (0x0B..0x0C, RFC 3927 §2.5),
// responder-dispatch (0x0D, RFC 3927 §2.7), steady-state cadence
// (0x0E, RFC 3927 §4 SHOULD NOT periodic gratuitous), or conflict-
// resolution rate-limit (0x0F..0x12, RFC 3927 §2.2.1).
// Spec invariant ↔ flavor is one-to-one — adding a new
// flavor without a backing spec invariant is a category violation
// (`feedback_frozen_spec_is_evidence.md`). The cadence cluster B
// (_09/_10 / _05/_06) does NOT need a flavor: the existing six timing
// knobs of `OpStartLLAutoconf` already parameterise interval / count,
// so cadence-violation negatives pass 100 ms timing knobs through the
// standard 0x0C opcode.
inline constexpr std::uint8_t kFlavorNone                          = 0x00;
inline constexpr std::uint8_t kFlavorSenderIpNonzero               = 0x01;  // RFC 3927 §2.1.1 sender_proto_ip MUST=0
inline constexpr std::uint8_t kFlavorTargetOutsidePrefix           = 0x02;  // RFC 3927 §2.1   target in 169.254/16 MUST
inline constexpr std::uint8_t kFlavorTargetInReservedRange         = 0x03;  // RFC 3927 §2.1   third octet ∈ [1,254] MUST
inline constexpr std::uint8_t kFlavorTargetHwNonzero               = 0x04;  // RFC 3927 §2.2.1 target_hw SHOULD=0
inline constexpr std::uint8_t kFlavorSenderHwWrong                 = 0x05;  // RFC 3927 §2.2.1 sender_hw=DUT MAC MUST
inline constexpr std::uint8_t kFlavorAnnounceEthDstUnicast         = 0x06;  // RFC 3927 §2.4   Announce eth_dst=broadcast MUST
inline constexpr std::uint8_t kFlavorAnnounceSenderTargetMismatch  = 0x07;  // RFC 3927 §2.4   Announce sender_ip==target_ip MUST
inline constexpr std::uint8_t kFlavorAnnounceSenderHwWrong         = 0x08;  // RFC 3927 §2.4   Announce sender_hw=DUT MAC MUST
inline constexpr std::uint8_t kFlavorAnnounceTargetHwNonzero       = 0x09;  // RFC 3927 §2.4   Announce target_hw=00:..:00 SHOULD
// Probe-shape flavor appended at 0x0A (after the Announce block) so the
// existing wire values stay stable; flavor grouping is by comment, not value.
inline constexpr std::uint8_t kFlavorProbeEthDstUnicast            = 0x0A;  // RFC 3927 §2.1.1 Probe eth_dst=broadcast MUST
// Defending-Reply-shape flavors for _16 + CONFLICT_11 (RFC 3927 §2.5).
inline constexpr std::uint8_t kFlavorReplySenderIpWrong           = 0x0B;  // RFC 3927 §2.5   Reply sender_proto_ip=committed LL MUST
inline constexpr std::uint8_t kFlavorReplyEthDstUnicast           = 0x0C;  // RFC 3927 §2.5   Reply eth_dst=broadcast MUST
// Responder-dispatch flavor (not a frame-field mutation): makes the
// post-claim responder answer ARP Requests for unclaimed targets.
inline constexpr std::uint8_t kFlavorReplyToArbitraryTarget       = 0x0D;  // RFC 3927 §2.7   answer only own claimed LL MUST
// Steady-state behavioral flavor (not a frame-field mutation): makes the
// committed host re-emit the Announce-shaped gratuitous ARP on a cadence.
inline constexpr std::uint8_t kFlavorEmitPeriodicGratuitous       = 0x0E;  // RFC 3927 §4     no periodic gratuitous ARP SHOULD NOT
// Conflict-resolution behavioral flavors (not frame-field mutations): each
// violates one RFC 3927 §2.2.1 rate-limit invariant at a specific point in
// the §4.5.6.2 _14/_15 conflict sequence, so the run is conformant up to
// that guard and violates exactly there. Read by runLoop's conflict loop, a
// passive break in all three emit-builder switches.
inline constexpr std::uint8_t kFlavorReprobeStaleCycle            = 0x0F;  // RFC 3927 §2.2.1 step 11 fresh address each conflict cycle MUST
inline constexpr std::uint8_t kFlavorSkipFirstRateLimitSilence    = 0x10;  // RFC 3927 §2.2.1 silent through 1st RATE_LIMIT_INTERVAL MUST
inline constexpr std::uint8_t kFlavorReprobeStalePostSilence      = 0x11;  // RFC 3927 §2.2.1 step 58 fresh post-rate-limit re-probe MUST
inline constexpr std::uint8_t kFlavorSkipSecondRateLimitSilence   = 0x12;  // RFC 3927 §2.2.1 rate-limit persists into 2nd window MUST

// `OpSetEgressFlavor` field-fault catalog (lwIP fixture egress hook). Distinct from
// the §4.5 link-local autoconf kFlavor* above (OpStartLLAutoconfBuggy). The DUT
// emits a frame legitimately and the netif link-output hook rewrites ONE header
// field on the way out (NOT recomputing the checksum — each guard reads the mutated
// field, and libpcap delivers the checksum-stale frame regardless), routed by the
// lwIP fixture glue, never by lwIP itself. One contiguous catalog across protocols;
// the flavor name carries the protocol+field. A field shared by a request-shape and a
// reply-shape case (htype, hlen) uses ONE flavor — the offset is identical and the
// case's provocation selects which frame. TCP being stateful, its flavors are
// segment-selective (gated on the segment the case observes) so the fault never
// breaks the handshake the observed segment depends on.
inline constexpr std::uint8_t kEgressFaultNone        = 0x00;
// ARP-over-Ethernet (no checksum):
inline constexpr std::uint8_t kArpFaultOpcodeWrong     = 0x01;  // RFC 826 opcode: ARP_07/ARP_12 (request MUST be 1)
inline constexpr std::uint8_t kArpFaultHwTypeWrong     = 0x02;  // RFC 826 htype:  ARP_08/ARP_46 (MUST be 1, Ethernet)
inline constexpr std::uint8_t kArpFaultProtoTypeWrong  = 0x03;  // RFC 826 ptype:  ARP_09 (MUST be 0x0800, IPv4)
inline constexpr std::uint8_t kArpFaultHwLenWrong      = 0x04;  // RFC 826 hlen:   ARP_10/ARP_47 (MUST be 6)
inline constexpr std::uint8_t kArpFaultProtoLenWrong   = 0x05;  // RFC 826 plen:   ARP_11 (MUST be 4)
// IPv4/UDP (the egress hook rewrites the named field; the resulting checksum
// mismatch is immaterial — each guard reads the field, and the checksum flavor
// invalidates the checksum field directly):
inline constexpr std::uint8_t kUdpFaultSrcPortWrong    = 0x06;  // RFC 768 src port:  §4.6.5.4 UDP_FIELDS_01
inline constexpr std::uint8_t kUdpFaultDstPortWrong    = 0x07;  // RFC 768 dst port:  §4.6.5.4 UDP_FIELDS_02
inline constexpr std::uint8_t kUdpFaultLengthWrong     = 0x08;  // RFC 768 length:    §4.6.5.4 UDP_FIELDS_06/07 + §4.6.5.3 UDP_Padding_02
inline constexpr std::uint8_t kUdpFaultChecksumWrong   = 0x09;  // RFC 768 checksum:  §4.6.5.4 UDP_FIELDS_13/14
// TCP (segment-selective; the flavor names the field + the segment it targets):
inline constexpr std::uint8_t kTcpFaultSynAckAckWrong   = 0x0A;  // RFC 793 ack num:  §4.8 TCP_SEQUENCE_01/03/04 (passive-open SYN,ACK acks tester ISN+1)
inline constexpr std::uint8_t kTcpFaultDataChecksumWrong = 0x0B; // RFC 793 checksum: §4.8 TCP_CHECKSUM_03 (data segment) + §4.8 TCP_HEADER_01 (data segment header validity)
inline constexpr std::uint8_t kTcpFaultRstSeqWrong      = 0x0C;  // RFC 793 §3.9 seq:  §4.8 TCP_BASICS_04/05 + FLAGS_INVALID_02 (RST SEQ off the spec value)
inline constexpr std::uint8_t kTcpFaultSynMssZero       = 0x0D;  // RFC 1122 §4.2.2.6 MSS option: §4.8 TCP_MSS_OPTIONS_11 (active-OPEN SYN advertises a receive MSS)
inline constexpr std::uint8_t kTcpFaultSynMssDefault    = 0x0E;  // RFC 1122 §4.2.2.6 MSS value:  §4.8 TCP_MSS_OPTIONS_12 (advertised MSS differs from the 536 default)
// ICMPv4 (§4.3) + IPv4 header (§4.4) on a DUT ICMP message, gated per ICMP type so only
// the observed frame is touched: the Echo Reply (type 0) for echo id/seq + IPv4 ttl /
// header checksum (0x0F-0x12); the Destination Unreachable (type 3) for code (0x13):
inline constexpr std::uint8_t kIcmpFaultEchoIdWrong    = 0x0F;  // RFC 792 echo id:  §4.3 ICMPv4_TYPE_09 (reply echoes the request identifier)
inline constexpr std::uint8_t kIcmpFaultEchoSeqWrong   = 0x10;  // RFC 792 echo seq: §4.3 ICMPv4_TYPE_09 (reply echoes the request sequence)
inline constexpr std::uint8_t kIpv4FaultTtlZero        = 0x11;  // RFC 1122 §3.2.1.7 TTL:  §4.4 IPv4_TTL_01 (emitted TTL MUST be non-zero)
inline constexpr std::uint8_t kIpv4FaultHdrChecksumWrong = 0x12; // RFC 791 §3.1 header checksum: §4.4 IPv4_CHECKSUM_05
inline constexpr std::uint8_t kIcmpFaultDestUnreachCodeWrong = 0x13; // RFC 1122 §3.2.2.1 code: §4.3 ICMPv4_TYPE_18 (Protocol Unreachable code 2)
// TCP (§4.8) pure-ACK ack_num. Appended at the catalog tail (the value space is
// append-only; numeric grouping with the 0x0A-0x0E TCP block is not maintained for
// later additions). Gated on a pure DUT ACK — the flavor names the field, the caller's
// arm timing names which ACK: per-phase after the handshake for a data-elicited ACK
// (HEADER_02/05/06, ACKNOWLEDGEMENT_02/03), or armed up front for the single ACK of a
// SYN-SENT open (SEQUENCE_02). The handshake third leg (also a pure ACK) is escaped by
// the arm timing, not the gate.
inline constexpr std::uint8_t kTcpFaultPureAckNumWrong = 0x14;  // RFC 793 §3.9 ack num: §4.8 HEADER_02/05/06 + ACKNOWLEDGEMENT_02/03 + SEQUENCE_02
inline constexpr std::uint8_t kEgressFaultMax         = kTcpFaultPureAckNumWrong;

// `OpSetIngressFlavor` ingress-reaction catalog (lwIP fixture input hook). The
// reception cases where a conformant DUT's reaction to an inbound frame is itself
// the property under test, so there is no DUT egress field to corrupt: the input
// hook makes the buggy DUT exhibit the forbidden reaction the positive case proves
// absent. Four reaction kinds today: prohibited EMISSION (§4.2.4.2 ARP — the DUT
// must drop a malformed/foreign frame silently, the fault makes it reply/learn;
// §4.3 ICMPv4 — the DUT must stay silent for an Info Request / unknown type /
// bad-checksum Echo / broadcast or fragmented error trigger, the fault synthesizes
// the prohibited ICMP reply; §4.8 TCP — the DUT must silently drop an unacceptable
// segment, the fault synthesizes the prohibited TCP response, e.g. a RST after a
// pure ACK), prohibited ACCEPTANCE (§4.6.5.4 UDP — the DUT must
// discard a malformed datagram, the fault makes it accept and deliver it to the
// receive-counting app), and prohibited REJECTION (§4.6.5.4 UDP — the DUT must
// accept a valid edge-case datagram, the fault makes it drop one it must deliver).
// The ARP and ICMP emission faults synthesize a frame back to the inbound sender
// (the conformant DUT emits nothing, so there is no egress to corrupt — the netif
// input hook builds the forbidden frame itself); the UDP faults mutate or swallow
// the inbound datagram in place. One contiguous catalog; the flavor name carries
// the protocol + reaction.
inline constexpr std::uint8_t kIngressFaultNone          = 0x00;
// ARP-over-Ethernet prohibited emission:
inline constexpr std::uint8_t kArpFaultReplyToDropFrame  = 0x01;  // §4.2.4.2 reply-absence: ARP_21/27/37/42 (reply to a frame the DUT must drop)
inline constexpr std::uint8_t kArpFaultLearnFromDropFrame = 0x02;  // §4.2.4.2 drop-and-emit: ARP_22/28/38 (learn the dropped Response's address)
// UDP prohibited acceptance — the input hook zeroes the inbound datagram's UDP
// checksum field so lwIP's `chksum != 0` guard skips validation and delivers it. On
// lwIP this is the ONLY drop gate for these cases: the length-field mutants
// (FIELDS_09 length 0, _10 length > payload, DATAGRAMLENGTH_01 length < payload)
// break the checksum because the length field is checksum-covered, and FIELDS_15
// corrupts the checksum directly — so one "skip checksum validation" fault makes them
// all accepted. (FIELDS_08's sub-8-byte truncation drops earlier, at the UDP
// minimum-length gate, and is not faithfully faultable this way — see
// dut/lwip_dut/README.md.)
inline constexpr std::uint8_t kUdpFaultAcceptBadChecksum  = 0x03;  // §4.6.5.4 acceptance: UDP_FIELDS_09/10/15 + DATAGRAMLENGTH_01 (accept a datagram its checksum check must drop)
// UDP prohibited rejection — the input hook swallows the inbound data-listener UDP
// frame (never forwards it to lwIP) so the receive-counting app never sees a datagram
// the DUT must accept. Models a DUT that wrongly drops a valid edge-case datagram.
inline constexpr std::uint8_t kUdpFaultRejectValid       = 0x04;  // §4.6.5.4 rejection: UDP_FIELDS_03 (src port 0) / _16 (checksum 0) (drop a datagram it must accept)
// ICMPv4 prohibited emission (§4.3) — the input hook synthesizes the ICMP reply a
// conformant DUT must NOT send for the inbound trigger, addressed back to the
// trigger's sender with the DUT's own source identity (the DUT emits nothing, so
// there is no egress field to corrupt). The flavor names the reply type; the case's
// trigger frame selects which prohibited reply is in scope:
inline constexpr std::uint8_t kIcmpFaultSynthEchoReply    = 0x05;  // §4.3.3.2 TYPE_10 (bad-checksum Echo) / §4.3.3.1 ERROR_05 (unknown type): synthesize an Echo Reply (type 0)
inline constexpr std::uint8_t kIcmpFaultSynthInfoReply    = 0x06;  // §4.3.3.2 TYPE_16: synthesize an Information Reply (type 16, RFC 1122 §3.2.2.7 SHOULD NOT)
inline constexpr std::uint8_t kIcmpFaultSynthParamProblem = 0x07;  // §4.3.3.1 ERROR_03 (fragmented) / ERROR_04 (broadcast): synthesize a Parameter Problem (type 12)
// TCP behavioral prohibited emission (§4.8) — the input hook synthesizes a forbidden TCP
// response on the connection's 4-tuple (swapped from the inbound trigger; the synthesized
// source IP is the DUT's own netif address, so a multicast-destination trigger still yields
// a DUT-sourced reply). RFC 793 §3.9 guards check only the 4-tuple + flag, never seq/ack, so
// the synthesized segment needs no connection-state tracking. The flavor names the response;
// its dispatch gate names the trigger:
inline constexpr std::uint8_t kTcpSynthRst               = 0x08;  // §4.8.6.18 ACKNOWLEDGEMENT_04 + §4.8.6.7 FLAGS_PROCESSING_11 (duplicate ACK in EST, itself a pure ACK): synthesize a RST on a pure ACK (RFC 793 §3.9 MUST NOT)
inline constexpr std::uint8_t kTcpSynthAck               = 0x09;  // synthesize a challenge ACK on a SYN/PSH segment the DUT must drop (RFC 1122 §4.2.3.10 / RFC 793 §3.1; e.g. §4.8.6.16 HEADER_07/08/09/11, CHECKSUM_02 — not exhaustive, grep the kTcpSynthAck arm for the full set)
// §4.8 TCP must-not-respond family — synthesize a RST when the DUT receives a
// "disruptive" segment (one carrying RST, FIN, URG, or PSH) that RFC 793 §3.9
// requires it to process or drop WITHOUT emitting a response. The gate is the
// disruptive-flag union: it EXCLUDES a bare pure ACK and a bare SYN, so the
// handshake (SYN, SYN|ACK, third-leg ACK) and the tester's later auto-ACKs (e.g.
// closing_08's FW1->FW2 FIN-ACK) never trip it — only the case's deliberate
// trigger does. A synthesized RST trips every guard in this family (each fails on
// is_dut_rst, or on "any DUT segment" which a RST satisfies):
inline constexpr std::uint8_t kTcpSynthRstOnDisruptive   = 0x0A;  // §4.8 must-not-respond family: synthesize the prohibited RST (e.g. FLAGS_INVALID_01/03/04/15, FLAGS_PROCESSING_07/08, CLOSING_03/07/08/09/13, UNACCEPTABLE_02 — not exhaustive, grep the kTcpSynthRstOnDisruptive arm)
// Extends the §4.3 ICMP synth family above; numbered 0x0B (after the TCP synths)
// to avoid renumbering 0x05-0x0A — the dispatch keys on the value, not its order.
inline constexpr std::uint8_t kIcmpFaultSynthTimeExceeded = 0x0B;  // §4.3.3.2 TYPE_04 (incomplete reassembly, fragment zero never arrives): synthesize a Time Exceeded (type 11)
inline constexpr std::uint8_t kIngressFaultMax           = kIcmpFaultSynthTimeExceeded;

// `OpSetAppFlavor` (0x1A) APP-LAYER reception-fault flavor byte. Distinct from the
// egress/ingress catalogs: those mutate or synthesize wire frames at the netif hook,
// whereas these fault the shared data listener (UpperTesterServer::dataListenerLoop /
// createUdpReceivePorts) — the application running on the DUT stack, below the netif
// glue's reach. Two reaction kinds: a DISCARD skip (the listener keeps a datagram RFC
// 1122 places a destination-address discard on) and a REPORT corruption (the §4.6.5.5
// UDP User-Interface Confirmation surfaces a wrong src port / src IP / payload / receive-
// port count for a correctly-received datagram — modelling a DUT whose receive operation
// returns wrong metadata, the only faithful site since the stack delivered it correctly).
// One contiguous catalog; the flavor name carries the policy or report field it faults.
inline constexpr std::uint8_t kAppFaultNone                   = 0x00;
// §4.4.4.5 ADDRESSING_02: the listener silently discards a datagram whose destination
// is the interface directed broadcast (limited broadcast 255.255.255.255 is kept).
// This flavor skips that discard so the DUT counts the directed broadcast it must
// drop (ipv4_addressing_02_neg). lwIP delivers directed broadcast to the INADDR_ANY
// data socket (IP_SOF_BROADCAST_RECV off), so the drop is genuinely the listener's.
inline constexpr std::uint8_t kAppFaultAcceptDirectedBroadcast = 0x01;
// §4.6.5.6 UDP_INTRODUCTION_02: the listener silently denies a datagram whose
// destination is the all-systems multicast 224.0.0.1 (the TC8 security profile inverts
// the RFC 1122 §4.1.1 SHOULD-allow). lwIP delivers it to the socket (ip4_input accepts
// every multicast destination with LWIP_IGMP off), so the deny is the listener's; this
// flavor skips it so the DUT counts the multicast it must drop (udp_introduction_02_neg).
inline constexpr std::uint8_t kAppFaultAcceptMulticast        = 0x02;
// §4.6.5.5 UDP User-Interface + §4.6.5.4 FIELDS Confirmation report corruption — the
// listener received the datagram correctly but reports a wrong field, so the positive's
// field guard goes from pass to fail. Each names the GetReceivedUdp / CreateUdpReceivePorts
// field it mangles; the conformant path (None) reports correctly (the _neg's fault-inert
// branch):
inline constexpr std::uint8_t kAppFaultReportWrongSrcPort     = 0x03;  // §4.6.5.5 UI_03: GetReceivedUdp src port (RFC 768 receive returns source port)
inline constexpr std::uint8_t kAppFaultReportWrongSrcIp       = 0x04;  // §4.6.5.5 UI_04: GetReceivedUdp src IP (RFC 768 receive returns source IP)
inline constexpr std::uint8_t kAppFaultReportWrongPayload     = 0x05;  // §4.6.5.5 UI_02: GetReceivedUdp payload bytes (RFC 768 receive returns data octets)
inline constexpr std::uint8_t kAppFaultMiscountPorts          = 0x06;  // §4.6.5.5 UI_01: CreateUdpReceivePorts actual_count (RFC 768 create N receive ports)
inline constexpr std::uint8_t kAppFaultReportWrongLength      = 0x07;  // §4.6.5.4 UDP_FIELDS_12: GetReceivedUdp payload length (RFC 768 receive returns datagram length)
inline constexpr std::uint8_t kAppFaultMax                    = kAppFaultReportWrongLength;

// `OpStartDhcpClient` fault-injection flavor byte (the append-only slot
// at param offset 24). A separate family from kFlavor* (which is the LL
// machine's frame-shape selector): these values name deliberately
// non-conformant Dhcpv4Client lifecycle code paths the §4.7 / §4.5.6.1
// negative cases drive. Like kFlavor*, the firmware enum is derived 1:1
// from these constants (single source of truth) and unknown values fall
// through to kDhcpFlavorNone, so a short or zero-padded request from an
// older caller can never accidentally inject a fault.
inline constexpr std::uint8_t kDhcpFlavorNone                     = 0x00;
// RFC 3927 §1.9 SHOULD NOT: a host with an operable routable address
// (here a bound DHCP lease) must not also assign an IPv4 Link-Local
// address on the same interface. This flavor makes tc8-dut's DHCP
// client emit one prohibited 169.254/16 ARP Probe after reaching BOUND
// — the leak §4.5.6.1 INTRO_01 guards against. Conformant emit (None)
// stays silent, so the negative case's compliant-silence branch is a
// live conformant-DUT outcome, not an infra-only dead branch.
inline constexpr std::uint8_t kDhcpFlavorLeakLinkLocalAfterBind   = 0x01;

// §4.7 DHCPDISCOVER field-shape mutants (Phase F). Each value makes the
// Dhcpv4Client emit one deliberately non-conformant field on its
// DUT-emitted messages so the matching §4.7 positive case's
// otherwise-dead field-violation branch becomes reachable, proving the
// guard catches a buggy client (mutation testing). Conformant emit
// (None) satisfies every invariant, so each negative's fail_compliant_*
// branch is a live conformant-DUT outcome, not an infra-only dead path.
// RFC clauses cited per value; see dut/dut_service/dhcpv4_client.cpp
// emitDhcpMessage for the wire-level mutation.
//
// RFC 2131 §3 / RFC 1497: the first four 'options' octets MUST be the
// magic cookie 99,130,83,99. Mutant corrupts the first cookie byte.
// (§4.7.6.2 PROTOCOL_01)
inline constexpr std::uint8_t kDhcpFlavorDiscoverMagicCookieCorrupt = 0x02;
// RFC 2131 §3: every DHCP message MUST carry Option 53 (DHCP Message
// Type). Mutant replaces the Option 53 TLV with PAD bytes.
// (§4.7.6.2 PROTOCOL_02)
inline constexpr std::uint8_t kDhcpFlavorDiscoverOmitMessageType    = 0x03;
// RFC 2131 §2: the reserved bits of the 'flags' field MUST be zero.
// Mutant sets a reserved bit. (§4.7.6.1 SUMMARY_04)
inline constexpr std::uint8_t kDhcpFlavorDiscoverReservedFlagsSet   = 0x04;
// RFC 2131 §3.1: the client broadcasts DHCPDISCOVER — IPv4 destination
// MUST be 255.255.255.255. Mutant unicasts it. (§4.7.6.3 ALLOCATING_01)
inline constexpr std::uint8_t kDhcpFlavorDiscoverDstUnicast         = 0x05;
// RFC 2131 §4.1: the last option MUST be the END option (0xFF). Mutant
// replaces END with a PAD byte. (§4.7.6.7 CONSTRUCTING_MESSAGES_01)
inline constexpr std::uint8_t kDhcpFlavorDiscoverDropEnd            = 0x06;
// RFC 2131 §4.1: a pre-binding DHCPDISCOVER has IP source = 0. Mutant
// sources it from a non-zero IP. (§4.7.6.7 CONSTRUCTING_MESSAGES_03)
inline constexpr std::uint8_t kDhcpFlavorDiscoverSrcNonzero         = 0x07;

// §4.7 SELECTING DHCPREQUEST field-shape mutants (Phase F). Like the
// Discover* family but gated to the post-OFFER DHCPREQUEST so the
// preceding DHCPDISCOVER stays conformant (the harness OFFER still
// matches it and the lifecycle reaches REQUEST). Each makes the
// emitted REQUEST violate one §4.7 invariant; the conformant client
// (None) satisfies them all.
//
// RFC 2131 §4.1: the REQUEST source IP is 0 in REQUESTING state.
// Mutant sources it from a non-zero IP. (§4.7.6.7 CM_04)
inline constexpr std::uint8_t kDhcpFlavorRequestSrcNonzero          = 0x08;
// RFC 2131 §3.1: the SELECTING REQUEST is broadcast. Mutant unicasts
// it. (§4.7.6.3 ALLOCATING_05)
inline constexpr std::uint8_t kDhcpFlavorRequestDstUnicast          = 0x09;
// RFC 2131 §4.3.2: the REQUEST 'ciaddr' is 0 in REQUESTING state.
// Mutant fills it with the requested address. (§4.7.6.8 REQUEST_01)
inline constexpr std::uint8_t kDhcpFlavorRequestCiaddrNonzero       = 0x0A;
// RFC 2131 §3.1: the REQUEST echoes the OFFER's server-id in Option 54.
// Mutant writes a wrong server-id. (§4.7.6.3 ALLOCATING_03)
inline constexpr std::uint8_t kDhcpFlavorRequestServerIdCorrupt     = 0x0B;
// RFC 2131 §4.3.2: the REQUEST carries the offered IP in Option 50.
// Mutant writes a wrong requested IP. (§4.7.6.8 REQUEST_02)
inline constexpr std::uint8_t kDhcpFlavorRequestRequestedIpCorrupt  = 0x0C;

// §4.7 RENEWING/REBINDING (reacquisition) DHCPREQUEST field-shape mutants
// (Phase F). Gated to the reacquisition REQUEST (ciaddr != 0) so the
// preceding DISCOVER + SELECTING REQUEST stay conformant and the
// lifecycle reaches BOUND. RFC 2131 §4.3.6 table 5 forbids Option 50 +
// Option 54 in RENEWING and REBINDING REQUESTs alike (one invariant),
// so the include mutants serve both phases.
//
// RFC 2131 §4.3.6 table 5: reacquisition REQUEST MUST NOT carry Option 54
// (Server Identifier). Mutant force-includes it. (§4.7.6.8 REQUEST_06/_09)
inline constexpr std::uint8_t kDhcpFlavorReacqRequestIncludeServerId    = 0x0D;
// RFC 2131 §4.3.6 table 5: reacquisition REQUEST MUST NOT carry Option 50
// (Requested IP). Mutant force-includes it. (§4.7.6.8 REQUEST_07/_10)
inline constexpr std::uint8_t kDhcpFlavorReacqRequestIncludeRequestedIp = 0x0E;
// RFC 2131 §4.4.5: reacquisition REQUEST 'ciaddr' MUST equal the bound IP.
// Mutant writes a wrong ciaddr. (§4.7.6.8 REQUEST_08/_11)
inline constexpr std::uint8_t kDhcpFlavorReacqRequestCiaddrWrong        = 0x0F;
// RFC 2131 §4.4.5: the RENEWING REQUEST MUST be unicast to the server-id.
// Mutant sends it to a wrong destination. (§4.7.6.7 CM_02 / §4.7.6.8
// REACQUISITION_01)
inline constexpr std::uint8_t kDhcpFlavorRenewingRequestDstWrong        = 0x10;
// RFC 2131 §4.4.5: the REBINDING REQUEST MUST be broadcast. Mutant
// unicasts it to a sentinel distinct from both the broadcast and the
// server-id, so the harness can tell a unicast REBINDING apart from a
// RENEWING retransmission (which is unicast to the server). (§4.7.6.8
// REQUEST_12)
inline constexpr std::uint8_t kDhcpFlavorRebindingDstUnicast            = 0x11;

// §4.7.6.9 INIT_ALLOC duplicate-address-detection (DAD) reaction mutants
// (Phase F). The post-BOUND DAD sequence (ARP Probe -> conflict-listen ->
// DHCPDECLINE | gratuitous ARP Announce) carries a checkable field shape;
// each mutant corrupts exactly one field of one reaction so the matching
// _neg case's violation guard becomes reachable. Applied in emitArpProbe /
// emitArpAnnounce / emitDhcpMessage (Decline phase); the conformant path
// (kDhcpFlavorNone) emits the correct shape, which is the _neg's live
// fail_compliant outcome.
//
// RFC 2131 §4.4.1 / RFC 5227 §2.1.1: the ARP Probe MUST carry
// sender_proto_ip = 0 (the client has not yet claimed the address).
// Mutant writes a non-zero sender IP. (INIT_ALLOC_08)
inline constexpr std::uint8_t kDhcpFlavorProbeSenderIpNonzero           = 0x12;
// RFC 2131 §4.4.1 / table 5: the DHCPDECLINE MUST carry the declined
// address in Option 50 (Requested IP Address). Mutant writes a wrong
// Option 50 value. (INIT_ALLOC_09)
inline constexpr std::uint8_t kDhcpFlavorDeclineRequestedIpWrong        = 0x13;
// RFC 2131 §4.4.1: the gratuitous ARP Announce MUST carry the committed
// (bound) IP as sender_proto_ip. Mutant writes a wrong sender IP.
// (INIT_ALLOC_10)
inline constexpr std::uint8_t kDhcpFlavorAnnounceSenderIpWrong          = 0x14;

// §4.7 SELECTING DHCPREQUEST ↔ DISCOVER continuity mutants (Phase F). RFC
// 2131 requires the post-OFFER REQUEST to carry the same identifying field
// values the originating DISCOVER did. Each mutant corrupts exactly one of
// those fields on the SELECTING REQUEST (gated to DhcpPhase::Selecting in
// emitDhcpMessage), leaving the DISCOVER conformant so the OFFER still
// matches and the lifecycle reaches the REQUEST under test. The conformant
// path (kDhcpFlavorNone) echoes the DISCOVER's values, which is the _neg's
// live fail_compliant outcome.
//
// RFC 2131 §4.3.2: the REQUEST's BOOTP 'secs' MUST equal the DISCOVER's.
// Mutant writes a nonzero 'secs' (the conformant client emits 0 in both).
// (§4.7.6.3 ALLOCATING_04)
inline constexpr std::uint8_t kDhcpFlavorRequestSecsMismatch            = 0x15;
// RFC 2131 §4.3.2 / §4.4.1: the REQUEST MUST echo the DISCOVER's 'xid'
// (which the OFFER carries). Mutant emits a different xid. (§4.7.6.9
// INIT_ALLOC_06)
inline constexpr std::uint8_t kDhcpFlavorRequestXidMismatch             = 0x16;
// RFC 2131 §4.3.6: if the DISCOVER carries Option 55 (Parameter Request
// List), the REQUEST MUST repeat the same byte sequence. Mutant corrupts
// one list byte. (§4.7.6.5 PARAMETERS_04)
inline constexpr std::uint8_t kDhcpFlavorRequestParamListMismatch       = 0x17;

// §4.7 DHCPDISCOVER / SELECTING REQUEST identity-field mutants (Phase F).
// Each corrupts exactly one BOOTP identity field the DUT emits, gated to
// its phase in emitDhcpMessage; the conformant path (kDhcpFlavorNone)
// emits the correct shape, which is the _neg's live fail_compliant outcome.
//
// RFC 2131 §4.4.1: the DHCPDISCOVER's 'ciaddr' MUST be 0 in INIT state.
// Mutant writes a nonzero ciaddr. (§4.7.6.9 INIT_ALLOC_02)
inline constexpr std::uint8_t kDhcpFlavorDiscoverCiaddrNonzero          = 0x18;
// RFC 2131 §4.4.1: the DHCPDISCOVER's 'chaddr' MUST be the client's
// hardware address. Mutant writes a different chaddr (the L2 source MAC
// stays the real one). (§4.7.6.9 INIT_ALLOC_03)
inline constexpr std::uint8_t kDhcpFlavorDiscoverChaddrMismatch         = 0x19;
// RFC 2131 §3: every DHCP message MUST carry Option 53 (Message Type).
// Mutant drops Option 53 from the SELECTING REQUEST. (§4.7.6.2 PROTOCOL_03)
inline constexpr std::uint8_t kDhcpFlavorRequestOmitMessageType         = 0x1A;

// §4.7 SELECTING-phase input-validation mutants (Phase F, prohibited).
// RFC 2131 §4.4.1 requires the client to silently discard a reply that
// fails validation; a conformant client therefore stays silent (no
// DHCPREQUEST), which is the _neg's live fail_compliant outcome. Each
// mutant relaxes one pollForReply acceptance gate so the buggy client
// wrongly proceeds to DHCPREQUEST. Behavioural (no emitted-field change):
// emitDhcpMessage treats them as conformant emits.
//
// RFC 2131 §4.4.1: a DHCPOFFER whose 'xid' does not match the most recent
// DHCPDISCOVER MUST be silently discarded. Mutant accepts it. (INIT_ALLOC_04)
inline constexpr std::uint8_t kDhcpFlavorAcceptMismatchedXidOffer       = 0x1B;
// RFC 2131 §4.4.1: a DHCPACK arriving in INIT/SELECTING (no accepted
// OFFER) MUST be silently discarded. Mutant proceeds on it. (INIT_ALLOC_05)
inline constexpr std::uint8_t kDhcpFlavorProceedOnLoneAck               = 0x1C;

// `OpConditionArpCache` action byte. Each value renders one TC8
// §4.2.4.2 ARP_48/49 "DUT CONFIGURE" / "TESTER waits" procedure step
// against the DUT's own ARP-table lifecycle:
//
//   * FlushAll — step 1 "clear the dynamic entries in the ARP Cache
//     of <DIface-0>". `param` is ignored. Per-case DUT respawn
//     fixtures get this for free; a persistent external DUT renders
//     the step through this action.
//   * AgeBySeconds — compresses step 8/12's "TESTER waits up to
//     <DYNAMIC-ARP-CACHE-TIMEOUT> (+ tolerance) for the ARP cache to
//     get refreshed": the DUT advances its table aging by `param`
//     seconds of virtual time (the lwIP backend drives its 1 Hz
//     etharp timer `param` times under the core lock). Entries whose
//     accumulated age crosses the stack's timeout are expired exactly
//     as wall-clock aging would expire them — same code path, no
//     wall-clock cost.
inline constexpr std::uint8_t kArpConditionFlushAll     = 0x01;
inline constexpr std::uint8_t kArpConditionAgeBySeconds = 0x02;

// `OpQueryCapabilities` bitmap packing — bit (opcode % 8) of byte
// (opcode / 8). These helpers are the single source of the packing
// for every producer (each DUT server bakes its bitmap from its own
// implemented-opcode list at compile time) and consumer (the harness
// decoder tests bits off the wire bytes) — hand-rolled shifts at call
// sites is how the two ends would drift.
inline constexpr std::size_t kCapabilityBitmapBytes =
    static_cast<std::size_t>(kMaxProtocolOpcode) / 8u + 1u;

template <std::size_t N>
constexpr std::array<std::uint8_t, kCapabilityBitmapBytes>
makeCapabilityBitmap(const std::uint8_t (&opcodes)[N]) {
    std::array<std::uint8_t, kCapabilityBitmapBytes> bitmap{};
    for (std::size_t i = 0; i < N; ++i) {
        bitmap[opcodes[i] / 8u] |=
            static_cast<std::uint8_t>(1u << (opcodes[i] % 8u));
    }
    return bitmap;
}

// `len` is the wire-reported bitmap length — bytes beyond it read as
// zero (a shorter response from an older DUT means "those opcodes did
// not exist when it was built", which is exactly "not implemented").
inline constexpr bool capabilityBitSet(const std::uint8_t *bitmap,
                                       std::size_t len,
                                       std::uint8_t opcode) {
    const std::size_t byte = opcode / 8u;
    return byte < len &&
           (bitmap[byte] & (1u << (opcode % 8u))) != 0u;
}

}  // namespace tc8::ut
