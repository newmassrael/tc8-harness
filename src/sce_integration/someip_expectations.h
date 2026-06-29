#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace tc8 {

// Ceiling for an expected L7 payload supplied via `--expect payload=HH:..`
// and asserted by a SOME/IP ETS Method-Response echo cond. Echo payloads are
// small (primitives / short structs / short arrays); a token that exceeds this
// makes the parser reject it (fail-loud) rather than silently truncate.
inline constexpr std::size_t kMaxExpectedPayload = 256;

// Flat DTO for the expected values a TC8 §5.1 SOMEIPSRV case compares
// captured SD-entry fields against — carries configured SERVICE-ID-1
// identity supplied via CLI `--expect key=value`.
//
// Lives in its own header (rather than inside `someip_expected.h`) so
// `test_config.h` can aggregate it without pulling in the full
// `SomeIpExpected` layout, and so ADL-dispatched helpers on the Named
// Context types can include `test_config.h` without a cycle.
struct SomeIpExpectations {
    std::uint16_t service_id = 0;
    std::uint16_t instance_id = 0;
    std::uint8_t major_version = 0;
    std::uint32_t ttl = 0;
    std::uint32_t minor_version = 0;
    // Type 2 entry field — SubscribeEventgroup / Ack entries carry this
    // instead of minor_version. Used by FORMAT_28.
    std::uint16_t eventgroup_id = 0;

    // Endpoint values consumed by §5.1.5.5 SOMEIPSRV_OPTIONS guards.
    // Each case verifies one field of an IPv4 Endpoint Option emitted
    // by the DUT in OfferService. Stored in network byte order to
    // align with `parseSdOptionsInto` (sd_options[].ipv4 uses NBO via
    // memcpy of wire bytes). 0 stays as the unset sentinel.
    std::uint32_t dut_iface_ip = 0;        // SERVER1-IP-ADDR (OPTIONS_04)
    std::uint16_t udp_port = 0;            // SERVICE-ID-1 UDP port (OPTIONS_07)
    std::uint16_t tcp_port = 0;            // SERVICE-ID-1 TCP port (OPTIONS_15)

    // SD multicast destination IP — `<SOME_IP_MULTICAST_IP_ADDR>` per
    // SOMEIPSD §4.2 default (vsomeip.json `service-discovery.multicast`
    // for tc8-dut). §5.1.5.4 SD_BEHAVIOR_03/_04 verify the DUT's
    // OfferService reply is sent to this multicast group. Stored in
    // network byte order to match `parseIpv4Dotted` and
    // `SomeIpFrame::dst_ip` from the dissector. 0 stays as the
    // unset sentinel.
    std::uint32_t sd_multicast_ip = 0;

    // Multicast eventgroup endpoint — IPv4 Multicast Option fields
    // emitted by vsomeip in a SubscribeEventgroupAck for an eventgroup
    // configured with a multicast endpoint
    // (dut/dut_service/vsomeip.json eventgroup 0x0008 →
    // 224.244.224.246:30495). §5.1.5.5 OPTIONS_11 verifies the IP,
    // OPTIONS_14 verifies the port. Stored in network byte order
    // (mcast_ipv4) to align with `SdOption::ipv4` (NBO) and host
    // order (mcast_port) for direct comparison against decimal
    // literals in SCXML cond expressions.
    std::uint32_t mcast_ipv4 = 0;
    std::uint16_t mcast_port = 0;

    // Tester's OWN subscribe endpoint — the address/port the DUT must send a
    // unicast SubscribeAck/Nack or event Notification back to. Lets a case assert
    // `captured.dst_ip == expected.tester_ipv4` (and dst_port) for the
    // destination half, which the DUT-side fields above cannot express. Network
    // byte order (tester_ipv4) to match `SomeIpCaptured::dst_ip`; host order
    // (tester_udp_port). Supplied via `--expect tester_ipv4=`/`tester_udp_port=`
    // (the tester iface IP the runner already knows). 0 stays the unset sentinel.
    std::uint32_t tester_ipv4 = 0;
    std::uint16_t tester_udp_port = 0;

    // Second tester/ECU source IP (IP_ADDRESS_2) — the spec's other deployment
    // "test variable" ("arbitrary IPv4 unicast address, different from
    // IP_ADDRESS_1"), used by two-client Sender-IP cases that drive the DUT from
    // two distinct source IPs it must discriminate by Sender IP. Sibling of
    // `tester_ipv4`: network byte order to match `SomeIpCaptured::dst_ip` /
    // `src_ip`, supplied via `--expect tester_ipv4_2=<dotted>`. 0 stays the unset
    // sentinel. A deployment configures it — rather than the harness deriving
    // `tester_ipv4 + 1` — so IP_ADDRESS_2 is a guaranteed-free neighbour and can
    // never silently collide with the DUT's own address.
    std::uint32_t tester_ipv4_2 = 0;

    // Configured DUT timing thresholds — what an absolute-timing case compares
    // the captured inter-frame delta (`SomeIpCaptured::frame_delta_us()`)
    // against, so an SCXML cond reads e.g. `frame_delta_us() within
    // [sd_cyclic_offer_delay_ms ± sd_timing_tolerance_ms]` instead of a
    // hard-coded magic literal. Operator/config-derived (like dut_iface_ip),
    // supplied via `--expect <key>=<ms>`; 0 stays the unset sentinel. Generic
    // test infrastructure ("what timers the IUT was configured with"), not
    // protocol payload — so it belongs here, not in any OEM case.
    //
    // SOME/IP-SD start-up state-machine timers (Initial Wait / Repetition /
    // Main phase), per the SOMEIPSD service-discovery behaviour.
    std::uint32_t sd_initial_delay_min_ms = 0;
    std::uint32_t sd_initial_delay_max_ms = 0;
    std::uint32_t sd_repetition_base_delay_ms = 0;
    std::uint32_t sd_repetitions_max = 0;  // a run-count cap (REPETITIONS_MAX), not ms
    std::uint32_t sd_cyclic_offer_delay_ms = 0;
    std::uint32_t sd_request_response_delay_ms = 0;
    std::uint32_t sd_timing_tolerance_ms = 0;

    // SD raw-startup latency threshold: the residual service-discovery
    // activation latency measured with the configured INITIAL_DELAY forced to
    // 0, so the first Offer's delay reflects only the DUT's own start-up cost.
    // Distinct from sd_initial_delay_max_ms (the configured Initial-Wait MAX) —
    // reusing it would conflate two independent SD start-up test variables.
    std::uint32_t sd_raw_startup_ms = 0;

    // CAN-encapsulated SOME/IP cadence / delay timers (periodic cycle,
    // delay time after a message, start offset). The CAN Message IDs and
    // payload encoding stay OEM-side; only the configured timer values live
    // here, exactly as the SD timers above do.
    std::uint32_t can_ets_cycle_0_ms = 0;
    std::uint32_t can_ets_cycle_1_ms = 0;
    std::uint32_t can_delay_time_ms = 0;
    std::uint32_t can_start_offset_ms = 0;
    std::uint32_t can_timing_tolerance_ms = 0;

    // Expected L7 payload bytes for a Method-Response echo assertion,
    // supplied via `--expect payload=HH:HH:..`. `payload_len` is the count
    // of valid leading bytes (0 = unset). ETS echo conds compare it via
    // `captured.payload_equals(expected.payload_view())`; the negative
    // harness flips one byte to drive the observed_violation final.
    std::array<std::uint8_t, kMaxExpectedPayload> payload{};
    std::uint32_t payload_len = 0;
};

}  // namespace tc8
