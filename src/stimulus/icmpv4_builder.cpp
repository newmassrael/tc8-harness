#include "stimulus/icmpv4_builder.h"

#include <cstdint>
#include <thread>

#include "stimulus/arp_builder.h"
#include "stimulus/ipv4_frame_builder.h"
#include "wire/icmp_echo.h"

namespace tc8::stimulus {

std::vector<std::uint8_t> buildIcmpMessage(const IcmpMessageSpec &spec) {
    // Compose via the shared IPv4 layer: ICMP-specific body synthesis
    // here, IP header + checksum + fragmentation + options in
    // `buildIpv4Frame`. The two paths diverge on `raw_ip_payload`:
    //  * empty (pilot Echo Request / TYPE_{08,09,10,16,18,22},
    //    ERROR_{02,04,05}): synthesize 8 B ICMP header + payload via
    //    `buildIcmpEchoRequestBody`, then drop into the IP frame.
    //  * non-empty (ERROR_03 frag 1, TYPE_04): notional slice of an
    //    ICMP packet with no ICMP header of its own — hand through
    //    verbatim, no ICMP checksum computed. The DUT's options parser
    //    gates on fragment_offset != 0 without ever reaching the ICMP
    //    layer, so a checksumless payload is exactly what the wire
    //    requires for these two call sites.
    std::vector<std::uint8_t> ip_payload;
    if (!spec.raw_ip_payload.empty()) {
        ip_payload = spec.raw_ip_payload;
    } else if (spec.icmp_type_override.has_value() &&
               *spec.icmp_type_override == 13U) {
        // §4.3.3.2 TYPE_11 / TYPE_12 — ICMP Timestamp Request body.
        // Builder emits the 20 B fixed-shape body; payload_data /
        // payload_len are intentionally unused here (RFC 792 p17 fixes
        // the message size).
        ip_payload = buildIcmpTimestampRequestBody(
            spec.echo_id, spec.echo_seq,
            spec.timestamp_originate,
            spec.timestamp_receive,
            spec.timestamp_transmit,
            spec.icmp_type_override, spec.icmp_code_override,
            spec.corrupt_icmp_checksum);
    } else {
        ip_payload = ::tc8::wire::buildIcmpEchoRequestBody(
            spec.echo_id, spec.echo_seq,
            spec.payload_data, spec.payload_len,
            spec.icmp_type_override, spec.icmp_code_override,
            spec.corrupt_icmp_checksum);
    }

    Ipv4FrameSpec ip_spec{};
    ip_spec.src_mac     = spec.src_mac;
    ip_spec.dst_mac     = spec.dst_mac;
    ip_spec.src_ip      = spec.src_ip;
    ip_spec.dst_ip      = spec.dst_ip;
    ip_spec.ttl         = spec.ttl;
    ip_spec.ip_id       = spec.ip_id;
    ip_spec.ip_protocol = spec.ip_protocol_override.value_or(kIpProtoIcmp);
    ip_spec.ip_options  = spec.ip_options;
    ip_spec.more_fragments  = spec.more_fragments;
    ip_spec.fragment_offset = spec.fragment_offset;
    ip_spec.version_override      = spec.version_override;
    ip_spec.ihl_override          = spec.ihl_override;
    ip_spec.total_length_override = spec.total_length_override;
    ip_spec.corrupt_ip_checksum   = spec.corrupt_ip_checksum;

    return buildIpv4Frame(ip_spec, ip_payload);
}

int emitIcmpMessage(std::string_view iface,
                        const IcmpMessageSpec &spec,
                        const IcmpBootTiming &timing) {
    std::this_thread::sleep_for(timing.initial_wait);
    const auto frame = buildIcmpMessage(spec);
    const int rc = sendRawEthernet(frame, iface);
    // §4.3.3.2 TYPE_04 / §4.4.4.6 FRAGMENTS_02/03/04 — block for the
    // DUT's reassembly timer to elapse before returning; TestRunner
    // arms SCXML deadlines only after kickStimulus returns, so the
    // listen window opens AFTER the wait. Default 0 ms leaves the
    // pre-fragment stimulus timing intact for every other case.
    if (timing.post_send_wait.count() > 0) {
        std::this_thread::sleep_for(timing.post_send_wait);
    }
    return rc;
}

}  // namespace tc8::stimulus
