#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// TC8 §4.8.5 Upper Tester wire protocol.
//
// §4.8.5 asks for a second channel into the IUT, separate from the one
// under test and reached over its own UDP port, through which the
// tester can make the IUT act — emit a chosen kind of message — or
// report what it holds and what it has received.
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

// Big-endian u32 reader — the numeric value of a big-endian wire field (octet 0
// is the most significant byte). Use for scalar counters (rto, unacked, ...).
inline std::uint32_t readU32(const std::uint8_t *p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

// IPv4 address as it sits on the wire (big-endian), returned in network byte
// order in memory (octet 0 in the low byte). This matches the harness captured
// convention (UdpCaptured::ut_recv_src_ip) and the tc8::wire::ipv4ToDotted
// formatter — it is deliberately NOT readU32's numeric value; address fields
// stay in NBO, scalar counters decode via readU32.
inline std::uint32_t readIpv4Nbo(const std::uint8_t *p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
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

// Mask that recovers the request opcode from a response opcode (clears the
// response bit). Named so the split is not a bare 0x7F literal at call sites.
inline constexpr std::uint8_t kRequestOpcodeMask = static_cast<std::uint8_t>(~kResponseBit);

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

    // Request / Response: make the DUT emit a UDP datagram from
    // <src_port> to <dst_ip>:<dst_port> carrying <payload>, optionally
    // binding the transient socket to a caller-specified source IP.
    // The tc8-dut binds a transient UDP socket to
    // (src_ip_override OR iface_ip, src_port) and calls sendto; the
    // tester observes the emitted datagram via pcap. Used by
    // FRAGMENTS_05 (no src_ip override) so the step that has the DUT
    // send is an explicit RPC rather than an inferred
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

    // §4.8.6.2 TCP_CHECKSUM_03 needs a DUT-side application send.
    // The tc8-dut writes `payload` bytes to the connected
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

    // §4.8.6.8 TCP_CLOSING_07/_08 need a DUT-side application read.
    // The tc8-dut blocks in
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

    // §4.8.6.8 TCP_CLOSING_07/_08 need a DUT-side application close,
    // and both list a shutdown service primitive among their
    // prerequisites. The tc8-dut calls ::shutdown(fd, SHUT_WR) on the
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

    // §4.8.6.5 TCP_CALL_ABORT_02/_03 need a DUT-side application
    // abort. Linux exposes ABORT
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

    // §4.8.6.9 TCP_MSS_OPTIONS_06/_09/_10 need a DUT-side application
    // send of at least the larger announced MSS, so that segmentation
    // is forced. The tc8-dut allocates a `total_len`-byte buffer
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

    // §4.8.6.14 TCP_URGENT_PTR_04 needs a DUT-side application read.
    // The tc8-dut blocks in `::recv(fd, buf, expected_len, MSG_OOB)`
    // up to `timeout_ms`, returning whatever urgent bytes Linux
    // delivered through the out-of-band path. Default Linux
    // behaviour (SO_OOBINLINE off, sysctl_tcp_stdurg=0) places one
    // urgent byte at `urg_seq` in the OOB queue; recv(MSG_OOB)
    // returns exactly that single byte. The case asks that the read
    // hand back the urgent data alone, which holds iff the response
    // carries one byte equal to the expected urgent byte.
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

    // §4.6.5.5 UDP_USER_INTERFACE_01 has the DUT open ten receive
    // ports on <DIface-0>. The tc8-dut binds `count` UDP
    // SOCK_DGRAM sockets to (INADDR_ANY, ephemeral port=0); the kernel
    // assigns each a distinct ephemeral port. The created fds are held
    // open for the rest of the tc8-dut process lifetime, so the count
    // the case has to confirm is observable as
    // `actual_count == count`. Closed in `stop()`.
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
    // procedure conditions the DUT cache explicitly — ARP_48 empties
    // the dynamic entries, fixes the cache timeout at
    // <DYNAMIC-ARP-CACHE-TIMEOUT>, and later waits out that timeout
    // plus <ARP-TOLERANCE-TIME> for a refresh. The Linux reference DUT renders those
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

    // Arm a SOME/IP application-layer fault flavor (kEtsFault* catalog below) on the
    // reference tc8-dut's EnhancedTestability service (EtsImpl). A non-None flavor makes a
    // getter return a corrupted value, so a buggy DUT surfaces a field readback that does
    // not echo what was set (§5.1.6 SOMEIP_ETS field get/set guards). This is the SOME/IP
    // sibling of OpSetAppFlavor: the fault lives in the harness-owned EtsImpl method, above
    // the vendored vsomeip transport, so it is the only faithful SOME/IP fault site (the
    // wire serialization is vsomeip-owned). tc8-dut-only: the lwIP fixture carries no
    // SOME/IP service and never registers it, so the matching `_neg` capability-skips there.
    //
    // Params: <flavor:u8>. Status: kStatusOk; kStatusMalformed for a short request
    // or an unknown flavor byte.
    OpSetEtsFlavor = 0x1B,
};

// Top of the protocol's opcode value space — the highest opcode this
// header defines. Bump alongside every opcode addition; the adjacency
// to the enum keeps the two from drifting. Per-implementation maxima
// live with each DUT server (the reference tc8-dut and the lwIP DUT
// each answer OpPing with their own honest contiguous top, and
// OpQueryCapabilities with their exact implemented set — the
// reference DUT itself skips OpConditionArpCache, whose §4.2 cache
// conditioning rides netns sysctls instead).
inline constexpr std::uint8_t kMaxProtocolOpcode = OpSetEtsFlavor;

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
// flavor without a backing spec invariant is a category violation:
// a flavor exists to prove one stated guard can fire, and a fault no
// guard checks validates nothing. The cadence cluster B
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

// The EGRESS / INGRESS / APP / ETS fault-flavour catalogues used to live here and now
// live in `tc8/upper_tester_fault_catalog.h`. They were split out on 2026-09-25 because
// they grow every time a negative case needs a new mechanism while this contract does
// not, so carrying both made every flavour a whole-suite recompile
// (docs/tech-debt.md TD-44).
//
// ⚠ That sibling is deliberately NOT included from here. Including it would put every
// consumer of this contract back in the blast radius and undo the split with nothing
// failing to say so — the split is the ABSENCE of this include, which is why the absence
// is written down. Name a flavour, include that header.

// `OpStartDhcpClient` fault-injection flavor byte (the append-only slot at
// param offset 24). A separate family from kFlavor* (the LL machine's frame-
// shape selector): these name deliberately non-conformant Dhcpv4Client code
// paths the §4.7 / §4.5.6.1 negative cases drive.
//
// SINGLE SOURCE OF TRUTH: include/tc8/dhcpv4_flavors.def co-locates each
// flavor's name + value + routing domain. The constants below, the
// DhcpFlavorDomain map, the UT-server router (posix_ut_extensions.cpp), and the
// firmware enums (dhcpv4_client.h) all DERIVE from that one list — so a new
// flavor cannot be added without declaring its domain, and a wrong domain is a
// compile error (the dispatch-site switch loses/gains the enumerator under
// -Werror=switch), never a silently-misrouted vacuous _neg. Unknown bytes map
// to None (conformant), so a short/zero-padded request from an older caller can
// never accidentally inject a fault.
inline constexpr std::uint8_t kDhcpFlavorNone = 0x00;
#define TC8_DHCP_FLAVOR(Name, value, Domain) \
    inline constexpr std::uint8_t kDhcpFlavor##Name = value;
#include "dhcpv4_flavors.def"
#undef TC8_DHCP_FLAVOR

// Routing domain for the flavor byte. The UT server switches on
// dhcpFlavorDomain() to set exactly one of Params.{flavor, arp_flavor,
// behavior_flavor, chaddr_override}. Generated from the same .def, so the
// router can never disagree with the enum partition.
enum class DhcpFlavorDomain : std::uint8_t {
    None,
    Message,
    Arp,
    Behavior,
    ChaddrOverride,
};

inline constexpr DhcpFlavorDomain dhcpFlavorDomain(std::uint8_t fb) {
    switch (fb) {
#define TC8_DHCP_FLAVOR(Name, value, Domain) \
        case value: return DhcpFlavorDomain::Domain;
#include "dhcpv4_flavors.def"
#undef TC8_DHCP_FLAVOR
        default: return DhcpFlavorDomain::None;  // None (0x00) + unknown = conformant
    }
}

// `OpConditionArpCache` action byte. Each value renders one TC8
// §4.2.4.2 ARP_48/49 "DUT CONFIGURE" / "TESTER waits" procedure step
// against the DUT's own ARP-table lifecycle:
//
//   * FlushAll — the step that empties the dynamic entries on
//     <DIface-0>. `param` is ignored. Per-case DUT respawn
//     fixtures get this for free; a persistent external DUT renders
//     the step through this action.
//   * AgeBySeconds — compresses the later wait for the cache to
//     refresh, <DYNAMIC-ARP-CACHE-TIMEOUT> plus tolerance: the DUT
//     advances its table aging by `param`
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

// Decoded Upper-Tester request/response — the single owner of the response
// wire OFFSETS (see docs/tech-debt.md TD-06). Both the verdict-path decoder
// (sce_integration/udp_captured.h fillUdpCapturedFromFrame) and the
// documentation-site exporter (cli/packet_summary.cpp utSummary) consume this;
// the verdict struct keeps only the subset of fields it asserts on. IP-address
// fields are stored in network byte order (octet 0 in the low byte — the
// harness captured convention, matching UdpCaptured::ut_recv_src_ip and
// formatted by tc8::wire::ipv4ToDotted); scalar fields hold the decoded host
// integer of the big-endian wire field. Each `*_valid` flag mirrors the
// consumer's body-length guard; only the field(s) matching `request_opcode`
// are meaningful.
struct UtResponse {
    bool present = false;             // len >= 2 (opcode + req_id present)
    std::uint8_t opcode = 0;         // full opcode byte (response bit set on a response)
    std::uint8_t request_opcode = 0;  // opcode & 0x7F (the request family)
    std::uint8_t req_id = 0;
    bool is_response = false;         // kResponseBit set on opcode
    bool has_status = false;          // len >= 3
    std::uint8_t status = 0;

    bool received_valid = false;                 // GetReceivedUdp: body >= 1
    std::uint8_t received = 0;
    bool recv_trailer_valid = false;             // GetReceivedUdp received==1 && body >= 9
    std::uint32_t recv_src_ip = 0;               // NBO (octet 0 low)
    std::uint16_t recv_src_port = 0;
    std::uint16_t recv_payload_len = 0;          // trailer-declared payload length
    const std::uint8_t *recv_payload = nullptr;  // -> trailer payload bytes
    std::uint32_t recv_payload_avail = 0;        // trailer payload bytes actually present

    bool established_valid = false;              // QueryTcpEstablished: body >= 1
    std::uint8_t established = 0;

    bool recv_len_valid = false;                 // Receive(Tcp|Oob): body >= 2
    std::uint16_t recv_len = 0;

    bool ll_address_valid = false;              // QueryLLAddress: body >= 4
    std::uint32_t ll_address = 0;                // NBO (octet 0 low)

    bool dhcp_lease_valid = false;              // QueryDhcpLease: body >= 4
    std::uint32_t dhcp_lease = 0;                // NBO (octet 0 low)

    bool tcp_info_valid = false;                // QueryTcpInfo: body >= 10
    std::uint8_t tcp_state = 0;
    std::uint32_t tcp_rto_us = 0;
    std::uint8_t tcp_retransmits = 0;
    std::uint32_t tcp_unacked = 0;

    bool create_count_valid = false;            // CreateUdpReceivePorts: body >= 1
    std::uint8_t create_actual_count = 0;
};

// Decode the per-opcode RESPONSE BODY (the bytes after <opcode|0x80> <req_id>
// <status>) into `r`, keyed on `r.request_opcode`. This is the single owner of
// the per-opcode trailer OFFSETS — every consumer routes here, whether it starts
// from a full observed datagram (decodeResponse, below) or already holds the
// correlated body (the active-control round trip in dut_control.h). Only the
// field(s) matching `request_opcode` are populated.
inline void decodeResponseBody(UtResponse &r, const std::uint8_t *body, std::uint32_t blen) {
    switch (r.request_opcode) {
        case OpGetReceivedUdp:
            if (blen >= 1) {
                r.received_valid = true;
                r.received = body[0];
                if (r.received == 1 && blen >= 9) {
                    r.recv_trailer_valid = true;
                    r.recv_src_ip = readIpv4Nbo(body + 1);
                    r.recv_src_port = readU16(body + 5);
                    r.recv_payload_len = readU16(body + 7);
                    r.recv_payload = body + 9;
                    r.recv_payload_avail = blen - 9;
                }
            }
            break;
        case OpQueryTcpEstablished:
            if (blen >= 1) {
                r.established_valid = true;
                r.established = body[0];
            }
            break;
        case OpReceiveTcpData:
        case OpReceiveTcpDataOob:
            if (blen >= 2) {
                r.recv_len_valid = true;
                r.recv_len = readU16(body);
            }
            break;
        case OpQueryLLAddress:
            if (blen >= 4) {
                r.ll_address_valid = true;
                r.ll_address = readIpv4Nbo(body);
            }
            break;
        case OpQueryDhcpLease:
            if (blen >= 4) {
                r.dhcp_lease_valid = true;
                r.dhcp_lease = readIpv4Nbo(body);
            }
            break;
        case OpQueryTcpInfo:
            if (blen >= 10) {
                r.tcp_info_valid = true;
                r.tcp_state = body[0];
                r.tcp_rto_us = readU32(body + 1);
                r.tcp_retransmits = body[5];
                r.tcp_unacked = readU32(body + 6);
            }
            break;
        case OpCreateUdpReceivePorts:
            if (blen >= 1) {
                r.create_count_valid = true;
                r.create_actual_count = body[0];
            }
            break;
        default:
            break;
    }
}

// Decode a full observed UT datagram (request or response) into UtResponse.
// Splits the header (opcode|req_id|status) and delegates the per-opcode body to
// decodeResponseBody (the offset SSOT). The caller layers its own gating on top
// (e.g. the verdict path also requires src_port == kPort before treating a
// decoded response as ours).
inline UtResponse decodeResponse(const std::uint8_t *payload, std::uint32_t len) {
    UtResponse r;
    if (payload == nullptr || len < 2) return r;
    r.present = true;
    r.opcode = payload[0];
    r.req_id = payload[1];
    r.is_response = (r.opcode & kResponseBit) != 0;
    r.request_opcode = static_cast<std::uint8_t>(r.opcode & kRequestOpcodeMask);
    // Only a RESPONSE carries a status byte + per-opcode body at these offsets;
    // a request's payload[2..] are parameters, so decode the response shape only
    // for responses. Callers that summarise requests use opcode/req_id above.
    if (!r.is_response) return r;
    if (len < 3) return r;
    r.has_status = true;
    r.status = payload[2];
    decodeResponseBody(r, payload + 3, len - 3);
    return r;
}

}  // namespace tc8::ut
