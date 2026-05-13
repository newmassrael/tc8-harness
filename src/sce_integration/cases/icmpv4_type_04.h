#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_04_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type04SM = ::SCE::Generated::icmpv4_type_04::icmpv4_type_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type04SM>
    : Icmpv4TypedBase<cases::Icmpv4Type04SM, std::uint8_t{11}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_04";
    static constexpr std::string_view kSpecSection = "4.3.3.2";
    static constexpr std::string_view kDescription =
        "DUT must not emit ICMP Time Exceeded (type=11) for a "
        "partially-received datagram when fragment 0 never arrives "
        "(RFC 792 p7 Time Exceeded MUST)";

    // Send a single IP fragment with MF=0, offset > 0, containing
    // what would be the last 8 B of a 16 B "constructed ICMP
    // packet". Fragment 0 is never sent. After the DUT's IP fragment
    // reassembly timer expires (spec `<ipIniReassembleTimeout>`;
    // Linux `net.ipv4.ipfrag_time` lowered to 3 s per-netns in
    // smoke-test.sh) the DUT's reassembly context times out; RFC 792
    // forbids Time Exceeded emission when fragment 0 never arrived,
    // so the DUT must emit no ICMP type=11 within the listen window.
    //
    // offset=1 in 8-octet units = 8 bytes, which is half of the
    // 16 B `kIcmpv4FragmentStimulusPacket`. The raw 8 B IP payload
    // is the second half of that literal.
    //
    // `post_send_wait=4s` defers the SCXML listen window until
    // after the per-netns reassembly timer (3 s) has expired, plus
    // 1 s of scheduler jitter absorption. TestRunner arms SCXML
    // deadlines only after `kickStimulus` returns, so the listen
    // window opens at approximately t+4 s and covers any post-
    // timeout Time Exceeded emission. The smoke-test.sh
    // `ipfrag_time=3` sysctl toggle + `CASE_TIMEOUT_SEC` override
    // must stay consistent with this wait + 3 s listen window +
    // margin. Harness invocations outside smoke-test.sh fall back
    // to Linux's 30 s default — the test still passes (longer wait
    // simply means the listen window opens later) but wall-time
    // reverts to ~33 s per run.
    //
    // L2 destination is DUT-unicast so the DUT's kernel accepts
    // the fragment via PACKET_HOST (Linux's IP reassembly path
    // enqueues on any pkt_type, but unicast keeps the envelope
    // symmetric with the rest of the §4.3 error cases and rules
    // out L2-dispatch skew as a confounder).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.dst_mac         = cfg.arp.dut_iface_mac;
        ov.more_fragments  = false;
        ov.fragment_offset = 1;
        ov.raw_ip_payload.assign(
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.begin() + 8,
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.end());
        ov.post_send_wait = std::chrono::milliseconds{4000};
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:             return "pass";
            case State::Fail_dut_replied: return "fail:dut_sent_time_exceeded_for_missing_fragment_zero";
            default:                      return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type04SM, icmpv4_type_04)
