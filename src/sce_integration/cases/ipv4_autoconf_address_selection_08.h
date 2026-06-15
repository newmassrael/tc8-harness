#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_08_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection08SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_08::ipv4_autoconf_address_selection_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection08SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection08SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_08";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT-emitted ARP Probe targets an address in the 169.254/16 "
        "link-local prefix (RFC 3927 §2.1, MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection08SM,
                  ipv4_autoconf_address_selection_08)
