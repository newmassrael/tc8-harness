#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/icmpv4_builder.h"

#include "ipv4_ttl_05_sm.h"

namespace tc8::sce::cases {

using Ipv4Ttl05SM = ::SCE::Generated::ipv4_ttl_05::ipv4_ttl_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

namespace ipv4_ttl_05 {

// One iteration's Echo Request: the TTL under test, told apart from the other
// iteration by its sequence number (the SCXML matches the Reply on the same pair).
inline ::tc8::stimulus::IcmpMessageSpec echoRequest(const ::tc8::TestConfig &cfg, std::uint8_t ttl,
                                                    std::uint16_t seq) {
    ::tc8::stimulus::IcmpMessageSpec spec{};
    spec.src_ip = cfg.icmpv4.tester_ip;
    spec.dst_ip = cfg.icmpv4.dut_iface_ip;
    spec.echo_id = cfg.icmpv4.echo_id;
    spec.echo_seq = seq;
    spec.ttl = ttl;
    return spec;
}

}  // namespace ipv4_ttl_05

// Echo Reply (type 0) dispatch, as the ICMPv4 Echo cases: the case grades the reply
// to its own two requests. IPv4-chapter requirements (the family default) keep the
// ARP exchange as its liveness anchor, which touches no IPv4 at all.
template <>
struct TestCaseTraits<cases::Ipv4Ttl05SM>
    : Icmpv4TypedBase<cases::Ipv4Ttl05SM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "IPv4_TTL_05";
    static constexpr std::string_view kDescription =
        "DUT replies to ICMPv4 Echo Requests carrying TTL=0 and TTL=1 (RFC 1122 "
        "section 3.2.1.7: host MUST NOT discard on TTL < 2)";

    // TTL=0 now; TTL=1 once the TTL=0 Reply has moved the machine on, so the second
    // window opens after the first closed and its silence is its own.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        const std::uint16_t seq = cfg.icmpv4.echo_seq;
        ::tc8::stimulus::emitIcmpMessage(ctx.iface, ipv4_ttl_05::echoRequest(cfg, std::uint8_t{0}, seq));
        std::string iface(ctx.iface);
        const ::tc8::stimulus::IcmpMessageSpec ttl1 =
            ipv4_ttl_05::echoRequest(cfg, std::uint8_t{1}, static_cast<std::uint16_t>(seq + 1U));
        ctx.scheduler.scheduleAfterStateEntry(static_cast<int>(State::Listening_ttl1), [iface, ttl1]() {
            ::tc8::stimulus::emitIcmpMessage(iface, ttl1);
        });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Ttl05SM, ipv4_ttl_05)
