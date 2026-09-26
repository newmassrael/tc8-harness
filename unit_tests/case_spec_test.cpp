// Unit tests for resolveCaseSpec / aliasAxisConflicts — which catalog entry
// answers which inventory axis. Pins the per-axis split a case alias depends on:
// the execution axes (stimulus, lane, negative row, DUT flavor) are the target's,
// while the verdict-excusing ones (platform_known_fail, expected) stay the alias's
// own, so a consumer's row can neither run a quietly different test under the
// target's name nor be excused by a deviation measured on another deployment.
//
// Fixtures are written to unique temp paths and removed in TearDown.

#include "sce_integration/case_spec.h"

#include <gtest/gtest.h>

#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace tc8::sce {
namespace {

CaseEntry entryIn(std::string_view suite, std::string_view id) {
    CaseEntry e;
    e.id = id;
    e.category = deriveCategory(id);
    e.suite = suite;
    return e;
}

class CaseSpecTest : public ::testing::Test {
protected:
    std::filesystem::path writeTemp(const std::string &name, const std::string &content) {
        const auto path = std::filesystem::temp_directory_path() /
                          ("tc8_casespec_" + std::to_string(::getpid()) + "_" + name);
        std::ofstream(path) << content;
        created_.push_back(path);
        return path;
    }

    void TearDown() override {
        for (const auto &p : created_) {
            std::error_code ec;
            std::filesystem::remove(p, ec);
        }
    }

    // The in-tree catalog: SOMEIPSRV_OPTIONS_11 carries every execution axis
    // plus a platform deviation; the vendor catalog holds the alias id.
    SpecInventory load(const std::string &vendor_overrides) {
        const auto tc8 = writeTemp("tc8.json", R"({
          "cases": [ {"case_id": "SOMEIPSRV_OPTIONS_11", "section": "5.1.5.4"} ]
        })");
        const auto vx = writeTemp("vx.json", R"({
          "suite": "vendorx",
          "cases": [ {"case_id": "VX_OPTIONS_11", "section": "7.1"} ]
        })");
        const auto ov = writeTemp("ov.json", R"({
          "overrides": {
            "SOMEIPSRV_OPTIONS_11": {
              "expect_overrides": ["eventgroup_id=0x0002"],
              "timing_serial": true,
              "neg_wrong_token": "service_id=0x9999",
              "neg_expect_fail": "fail:wrong_service_id",
              "vsomeip_cfg": "vsomeip-multi-instance.json",
              "vsomeip_env": ["TC8_DUT_INSTANCE_2=1"],
              "platform_known_fail": true,
              "platform_known_fail_verdict": "fail:deviation_on_the_linux_dut"
            })" + vendor_overrides + R"(
          }
        })");
        std::string err;
        auto inv = SpecInventory::load(tc8.string(), {vx.string()}, ov.string(), &err);
        EXPECT_TRUE(inv.has_value()) << err;
        return *inv;
    }

    std::vector<std::filesystem::path> created_;
};

TEST_F(CaseSpecTest, AnAuthoredCaseReadsOneEntryForBoth) {
    const auto inv = load("");
    const auto e = entryIn(kDefaultSuite, "SOMEIPSRV_OPTIONS_11");
    const auto spec = resolveCaseSpec(inv, e);
    ASSERT_NE(spec.own, nullptr);
    EXPECT_EQ(spec.own, spec.execution);
}

TEST_F(CaseSpecTest, AnAliasRunsTheTargetButKeepsItsOwnVerdictAxes) {
    const auto inv = load("");
    auto alias = entryIn("vendorx", "VX_OPTIONS_11");
    alias.alias_of = {kDefaultSuite, "SOMEIPSRV_OPTIONS_11"};

    const auto spec = resolveCaseSpec(inv, alias);
    ASSERT_NE(spec.own, nullptr);
    ASSERT_NE(spec.execution, nullptr);

    // Execution: the target's stimulus, lane, self-check and DUT.
    EXPECT_EQ(spec.execution->id, "SOMEIPSRV_OPTIONS_11");
    EXPECT_EQ(spec.execution->expect_overrides,
              (std::vector<std::string>{"eventgroup_id=0x0002"}));
    EXPECT_TRUE(spec.execution->timing_serial);
    EXPECT_EQ(spec.execution->neg_wrong_token, "service_id=0x9999");
    EXPECT_EQ(spec.execution->vsomeip_cfg, "vsomeip-multi-instance.json");

    // Own: the vendor catalog's section, and NOT the reference platform's
    // deviation — the target is excused on the reference DUT, the alias is not.
    EXPECT_EQ(spec.own->section, "7.1");
    EXPECT_FALSE(spec.own->platform_known_fail);
    EXPECT_TRUE(spec.own->expected);
}

TEST_F(CaseSpecTest, AnAliasWhoseCatalogOmitsItHasNoOwnEntry) {
    const auto inv = load("");
    auto alias = entryIn("vendorx", "VX_OPTIONS_99");
    alias.alias_of = {kDefaultSuite, "SOMEIPSRV_OPTIONS_11"};
    const auto spec = resolveCaseSpec(inv, alias);
    EXPECT_EQ(spec.own, nullptr);
    ASSERT_NE(spec.execution, nullptr);
    EXPECT_EQ(spec.execution->id, "SOMEIPSRV_OPTIONS_11");
}

TEST_F(CaseSpecTest, AnAliasMayDeclareItsOwnVerdictAxes) {
    const auto inv = load(R"(,
            "vendorx:VX_OPTIONS_11": { "platform_known_fail": true })");
    CaseRegistry reg;
    reg.add(entryIn(kDefaultSuite, "SOMEIPSRV_OPTIONS_11"));
    std::string err;
    ASSERT_TRUE(reg.addAlias({"vendorx", "VX_OPTIONS_11", kDefaultSuite, "SOMEIPSRV_OPTIONS_11"},
                             &err))
        << err;
    EXPECT_TRUE(aliasAxisConflicts(inv, reg).empty());
    EXPECT_TRUE(resolveCaseSpec(inv, *reg.find("vendorx", "VX_OPTIONS_11")).own->platform_known_fail);
}

// An execution axis on the alias's own entry would be silently ignored — the
// target's wins — so it is reported, naming the axis and both identities.
TEST_F(CaseSpecTest, AnAliasDeclaringAnExecutionAxisIsAConflict) {
    const auto inv = load(R"(,
            "vendorx:VX_OPTIONS_11": { "expect_overrides": ["eventgroup_id=0x0007"] })");
    CaseRegistry reg;
    reg.add(entryIn(kDefaultSuite, "SOMEIPSRV_OPTIONS_11"));
    std::string err;
    ASSERT_TRUE(reg.addAlias({"vendorx", "VX_OPTIONS_11", kDefaultSuite, "SOMEIPSRV_OPTIONS_11"},
                             &err))
        << err;

    const auto conflicts = aliasAxisConflicts(inv, reg);
    ASSERT_EQ(conflicts.size(), 1U);
    EXPECT_NE(conflicts[0].find("vendorx:VX_OPTIONS_11"), std::string::npos) << conflicts[0];
    EXPECT_NE(conflicts[0].find("SOMEIPSRV_OPTIONS_11"), std::string::npos) << conflicts[0];
    EXPECT_NE(conflicts[0].find("expect_overrides"), std::string::npos) << conflicts[0];
}

// The same declaration on an AUTHORED case of the vendor suite is that case's
// own business and no conflict at all.
TEST_F(CaseSpecTest, AnAuthoredCaseDeclaringExecutionAxesIsNotAConflict) {
    const auto inv = load(R"(,
            "vendorx:VX_OPTIONS_11": { "expect_overrides": ["eventgroup_id=0x0007"] })");
    CaseRegistry reg;
    reg.add(entryIn("vendorx", "VX_OPTIONS_11"));
    EXPECT_TRUE(aliasAxisConflicts(inv, reg).empty());
}

// The digest a consumer pins must describe the TARGET: an alias's entry is a copy
// of the target's traits and its execution axes are the target's, so the alias
// and the target it names must digest identically.
TEST_F(CaseSpecTest, AnAliasDigestsExactlyAsItsTarget) {
    const auto inv = load("");
    CaseRegistry reg;
    CaseEntry target = entryIn(kDefaultSuite, "SOMEIPSRV_OPTIONS_11");
    target.topology = 2;
    reg.add(target);
    std::string err;
    ASSERT_TRUE(reg.addAlias({"vendorx", "VX_OPTIONS_11", kDefaultSuite, "SOMEIPSRV_OPTIONS_11"},
                             &err))
        << err;
    const CaseEntry *t = reg.find(kDefaultSuite, "SOMEIPSRV_OPTIONS_11");
    const CaseEntry *a = reg.find("vendorx", "VX_OPTIONS_11");
    EXPECT_EQ(executionSurface(*a, resolveCaseSpec(inv, *a)),
              executionSurface(*t, resolveCaseSpec(inv, *t)));
}

TEST_F(CaseSpecTest, TheDigestMovesWithExecutionAndNotWithProse) {
    const auto inv = load("");
    CaseEntry e = entryIn(kDefaultSuite, "SOMEIPSRV_OPTIONS_11");
    const CaseSpec spec = resolveCaseSpec(inv, e);
    const std::string base = executionSurface(e, spec);
    EXPECT_EQ(base.size(), 16U);
    EXPECT_EQ(base, executionSurface(e, spec)) << "must be a pure function of its input";

    // Prose is not execution: rewording the description changes nothing.
    CaseEntry reworded = e;
    reworded.description = "the same test, described differently";
    EXPECT_EQ(executionSurface(reworded, spec), base);

    // A traits field that changes how the case runs moves it...
    CaseEntry recapped = e;
    recapped.required_capabilities = 0x20U;
    EXPECT_NE(executionSurface(recapped, spec), base);

    // ...and so does the target losing its inventory axes (stimulus override,
    // negative row, DUT flavor) — what an alias inherits from them.
    EXPECT_NE(executionSurface(e, CaseSpec{}), base);
}

// The consumer's pin travels with the alias entry; the target carries none.
TEST_F(CaseSpecTest, APinnedSurfaceRidesOnTheAliasOnly) {
    CaseRegistry reg;
    reg.add(entryIn(kDefaultSuite, "SOMEIPSRV_OPTIONS_11"));
    std::string err;
    ASSERT_TRUE(reg.addAlias({"vendorx", "VX_OPTIONS_11", kDefaultSuite, "SOMEIPSRV_OPTIONS_11",
                              "0123456789abcdef"},
                             &err))
        << err;
    EXPECT_EQ(reg.find("vendorx", "VX_OPTIONS_11")->alias_surface_pin, "0123456789abcdef");
    EXPECT_TRUE(reg.find(kDefaultSuite, "SOMEIPSRV_OPTIONS_11")->alias_surface_pin.empty());
}

}  // namespace
}  // namespace tc8::sce
