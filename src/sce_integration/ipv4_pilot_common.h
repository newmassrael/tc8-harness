#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>

#include "tc8/captured_event.h"
#include "sce_integration/ipv4_captured.h"
#include "sce_integration/test_config.h"
#include "stimulus/icmpv4_builder.h"

namespace tc8::sce::ipv4 {

// Per-case overrides for the §4.4 IPv4 pilot stimulus. All fields are
// optional; unset fields keep the `IcmpMessageSpec` defaults — which
// produce a well-formed Echo Request that the DUT's kernel accepts and
// replies to. Populate a field to test a specific malformation path:
//
//   * version               — §4.4.4.4 VERSION_04 (version != 4)
//   * ihl                   — §4.4.4.1 HEADER_02 / HEADER_08 (IHL != 5)
//   * total_length          — §4.4.4.1 HEADER_09 (total_length != actual)
//   * dst_ip                — §4.4.4.1 HEADER_04 / §4.4.4.5 ADDRESSING_03
//   * ttl                   — §4.4.4.3 TTL_05 (ttl=0)
//   * corrupt_ip_checksum   — §4.4.4.2 CHECKSUM_02 (flip header checksum)
//
// The struct layout is intentionally flat + POD-like so traits can
// construct one inline and rely on copy-elision. No constructor — add
// fields, don't add constructors.
struct StimulusOverrides {
    std::optional<std::uint8_t>  version;
    std::optional<std::uint8_t>  ihl;
    std::optional<std::uint16_t> total_length;
    std::optional<std::uint32_t> dst_ip;  // override `cfg.icmpv4.dut_iface_ip`
    std::optional<std::uint8_t>  ttl;
    bool                         corrupt_ip_checksum = false;
};

// Emit one ICMPv4 Echo Request from the tester, with optional per-field
// overrides. Default-constructed `ov` reproduces the pilot's good-path
// stimulus — the DUT's kernel replies with an Echo Reply the SCXML
// observes.
inline void emitStimulus(const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         const StimulusOverrides& ov = {}) {
    ::tc8::stimulus::IcmpMessageSpec spec{};
    spec.src_ip   = cfg.icmpv4.tester_ip;
    spec.dst_ip   = ov.dst_ip.value_or(cfg.icmpv4.dut_iface_ip);
    spec.echo_id  = ::tc8::stimulus::kIcmpEchoId;
    spec.echo_seq = ::tc8::stimulus::kIcmpEchoSeq;
    if (ov.ttl)          spec.ttl                   = *ov.ttl;
    if (ov.version)      spec.version_override      = ov.version;
    if (ov.ihl)          spec.ihl_override          = ov.ihl;
    if (ov.total_length) spec.total_length_override = ov.total_length;
    spec.corrupt_ip_checksum = ov.corrupt_ip_checksum;
    ::tc8::stimulus::emitIcmpMessage(iface, spec);
}

// Dispatch helper: select the Ipv4Frame variant from the captured event,
// mirror its fields into `c`, and raise the shared `Ipv4_observed`
// external event on the SM. Every §4.4 case uses this identical shape
// because the src_addr filter (tester vs DUT) lives inside the SCXML
// guard — traits don't have access to the `expected` context, so they
// can't discriminate here.
template <typename SM>
inline void dispatchIpv4Frame(typename SM::CapturedType& c, SM& sm,
                              const ::tc8::CapturedEvent& ev) {
    const auto* f = std::get_if<::tc8::Ipv4Frame>(&ev);
    if (f == nullptr) return;
    ::tc8::fillIpv4CapturedFromFrame(c, *f);
    const auto state_before = sm.getCurrentState();
    sm.raiseExternal(SM::PolicyType::Event::Ipv4_observed);
    sm.step();
    const auto state_after = sm.getCurrentState();
    if (state_after != state_before) {
        c.prev_observed_ts_us = c.observed_ts_us;
    }
}

}  // namespace tc8::sce::ipv4
