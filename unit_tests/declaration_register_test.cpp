// The declaration register (cli/declaration_register.h): what an operator can declare
// about the DUT, and the one place a case's declaration requirements are evaluated.
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "cli/declaration_register.h"
#include "sce_integration/declaration_requirement.h"
#include "sce_integration/test_config.h"

namespace {

using ::tc8::cli::DeclarationClass;
using ::tc8::sce::DeclarationRequirement;

// Every key of the declaration groups is a register row: a key written as a plain
// TC8_EXPECT_KEY in one of those groups would be declarable and unregistered.
TEST(DeclarationRegister, EveryDeclarationKeyIsARegisterRow) {
    EXPECT_EQ(::tc8::cli::declarationRegister().size(), ::tc8::cli::declarationGroupKeyCount());
}

TEST(DeclarationRegister, ItemsCarryTheirClassStandardAndValues) {
    const auto *rst = ::tc8::cli::findDeclaration("tcp.time_wait_rst");
    ASSERT_NE(rst, nullptr);
    EXPECT_EQ(rst->cls, DeclarationClass::PICS);
    EXPECT_EQ(rst->values, (std::vector<std::string_view>{"ends_connection", "ignored"}));
    EXPECT_FALSE(rst->standard.empty());

    const auto *cwnd = ::tc8::cli::findDeclaration("tcp.initial_cwnd_segments");
    ASSERT_NE(cwnd, nullptr);
    EXPECT_EQ(cwnd->cls, DeclarationClass::PIXIT);
    EXPECT_TRUE(cwnd->values.empty());

    ASSERT_NE(::tc8::cli::findDeclaration("network.vlan_id"), nullptr);
    EXPECT_EQ(::tc8::cli::findDeclaration("tcp.no_such_item"), nullptr);
}

TEST(DeclarationRegister, ADeclaredValueReadsInTheSpellingExpectTakes) {
    ::tc8::TestConfig cfg;
    EXPECT_FALSE(::tc8::cli::declaredValue(cfg, "tcp.time_wait_rst").has_value());
    cfg.tcp_declared.time_wait_rst = ::tc8::TimeWaitRstPolicy::kIgnored;
    cfg.tcp_declared.initial_cwnd_segments = 10;
    cfg.tcp_declared.congestion_control = "new_reno";
    cfg.network.vlan_id = 100;
    EXPECT_EQ(::tc8::cli::declaredValue(cfg, "tcp.time_wait_rst"), "ignored");
    EXPECT_EQ(::tc8::cli::declaredValue(cfg, "tcp.initial_cwnd_segments"), "10");
    EXPECT_EQ(::tc8::cli::declaredValue(cfg, "tcp.congestion_control"), "new_reno");
    EXPECT_EQ(::tc8::cli::declaredValue(cfg, "network.vlan_id"), "100");
    EXPECT_FALSE(::tc8::cli::declaredValue(cfg, "tcp.no_such_item").has_value());
}

// An undeclared item and a declared value the case does not run for are different skips,
// each naming the item.
TEST(DeclarationRequirements, UndeclaredAndExcludingValueAreDistinctSkips) {
    static constexpr DeclarationRequirement reqs[] = {{"tcp.time_wait_rst", "ends_connection"}};
    ::tc8::TestConfig cfg;
    EXPECT_EQ(::tc8::cli::unmetRequirement(reqs, 1, cfg), "undeclared_tcp_time_wait_rst");
    cfg.tcp_declared.time_wait_rst = ::tc8::TimeWaitRstPolicy::kIgnored;
    EXPECT_EQ(::tc8::cli::unmetRequirement(reqs, 1, cfg), "declared_tcp_time_wait_rst_ignored");
    cfg.tcp_declared.time_wait_rst = ::tc8::TimeWaitRstPolicy::kEndsConnection;
    EXPECT_FALSE(::tc8::cli::unmetRequirement(reqs, 1, cfg).has_value());
}

// A PIXIT requirement asks for a declaration, whatever its value.
TEST(DeclarationRequirements, AnyValueRequirementNeedsOnlyTheDeclaration) {
    static constexpr DeclarationRequirement reqs[] = {{"tcp.initial_cwnd_segments", {}}};
    ::tc8::TestConfig cfg;
    EXPECT_EQ(::tc8::cli::unmetRequirement(reqs, 1, cfg), "undeclared_tcp_initial_cwnd_segments");
    cfg.tcp_declared.initial_cwnd_segments = 4;
    EXPECT_FALSE(::tc8::cli::unmetRequirement(reqs, 1, cfg).has_value());
    EXPECT_FALSE(::tc8::cli::unmetRequirement(nullptr, 0, cfg).has_value());
}

// A requirement that can never be met as written is the case's defect, caught by name.
TEST(DeclarationRequirements, AMalformedRequirementIsNamed) {
    EXPECT_FALSE(::tc8::cli::malformedRequirement({"tcp.time_wait_rst", "ignored"}).has_value());
    EXPECT_FALSE(::tc8::cli::malformedRequirement({"tcp.initial_cwnd_segments", {}}).has_value());
    EXPECT_TRUE(::tc8::cli::malformedRequirement({"tcp.time_wait_rst", "rfc1337"}).has_value());
    EXPECT_TRUE(::tc8::cli::malformedRequirement({"tcp.timewait_rst", "ignored"}).has_value());
}

}  // namespace
