// Unit tests for the SpecInventory loader's D5 out-of-tree injection hook
// (--inventory-extra). Pins the merge behaviour, the loud-error-on-collision
// policy within one suite, back-compat of the 3-arg load, and that every axis
// resolves by (suite, id): a same-id case in another suite inherits nothing.
//
// Fixtures are written to unique temp paths and removed in TearDown, so
// the test leaves no scratch artifact in the workspace.

#include "sce_integration/spec_inventory.h"

#include <gtest/gtest.h>

#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

using tc8::sce::kDefaultSuite;
using tc8::sce::SpecInventory;

class SpecInventoryMergeTest : public ::testing::Test {
protected:
    std::filesystem::path writeTemp(const std::string &name, const std::string &content) {
        const auto path =
            std::filesystem::temp_directory_path() /
            ("tc8_specinv_" + std::to_string(::getpid()) + "_" + name);
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

    std::vector<std::filesystem::path> created_;
};

constexpr const char *kPrimary = R"({
  "cases": [
    {"case_id": "ARP_07", "section": "4.2.4.1", "split": "p041", "line": 10},
    {"case_id": "IPv4_HEADER_05", "section": "4.4.4.1", "split": "p061", "line": 20}
  ]
})";

constexpr const char *kExtra = R"({
  "cases": [
    {"case_id": "OEMX_DEMO_01", "section": "X.1", "split": "oem", "line": 1}
  ]
})";

TEST_F(SpecInventoryMergeTest, MergesExtraInventoryCases) {
    const auto primary = writeTemp("primary.json", kPrimary);
    const auto extra = writeTemp("extra.json", kExtra);

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {extra.string()}, "", &err);
    ASSERT_TRUE(inv.has_value()) << err;

    EXPECT_NE(inv->find(kDefaultSuite, "ARP_07"), nullptr);
    EXPECT_NE(inv->find(kDefaultSuite, "IPV4_HEADER_05"), nullptr);  // canonical UPPER
    EXPECT_NE(inv->find(kDefaultSuite, "OEMX_DEMO_01"), nullptr);     // merged from extra
    EXPECT_EQ(inv->cases().size(), 3u);
}

TEST_F(SpecInventoryMergeTest, CollisionIsLoudError) {
    const auto primary = writeTemp("primary.json", kPrimary);
    // Re-declares ARP_07 case-insensitively — collision is on the
    // canonical (UPPER) key, so `arp_07` must still trip the guard.
    const auto dup = writeTemp("dup.json", R"({"cases":[{"case_id":"arp_07"}]})");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {dup.string()}, "", &err);
    EXPECT_FALSE(inv.has_value());
    EXPECT_NE(err.find("collides"), std::string::npos) << err;
}

TEST_F(SpecInventoryMergeTest, MissingExtraIsError) {
    const auto primary = writeTemp("primary.json", kPrimary);

    std::string err;
    auto inv = SpecInventory::load(primary.string(),
                                   {"/nonexistent/tc8/extra.json"}, "", &err);
    EXPECT_FALSE(inv.has_value());
    EXPECT_NE(err.find("extra spec inventory"), std::string::npos) << err;
}

// TD-40: a named overrides file that cannot be opened is an error, never "no
// overrides" — reading it as absent would drop every per-case axis it carries.
// An EMPTY path is how a caller says there is no overrides file.
TEST_F(SpecInventoryMergeTest, NamedOverridesThatCannotOpenIsError) {
    const auto primary = writeTemp("primary.json", kPrimary);

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {}, "/nonexistent/tc8/overrides.json", &err);
    EXPECT_FALSE(inv.has_value());
    EXPECT_NE(err.find("/nonexistent/tc8/overrides.json"), std::string::npos) << err;

    err.clear();
    auto none = SpecInventory::load(primary.string(), {}, "", &err);
    ASSERT_TRUE(none.has_value()) << err;
    EXPECT_EQ(none->cases().size(), 2u);
}

TEST_F(SpecInventoryMergeTest, BackCompatThreeArgLoad) {
    const auto primary = writeTemp("primary.json", kPrimary);

    std::string err;
    auto inv = SpecInventory::load(primary.string(), "", &err);
    ASSERT_TRUE(inv.has_value()) << err;
    EXPECT_EQ(inv->cases().size(), 2u);
}

// --- expect_overrides axis (schema v6) ------------------------------------
//
// The per-case `--expect` tokens the harness appends after the driver's. The
// value lives here (one home); `runCase` applies it. These pin the loader half:
// that the array reaches SpecCase, that absence is empty (not a sentinel), and
// that the axis composes with a platform_known_fail entry rather than
// replacing it (SOMEIP_ETS_117 carried exactly that shape in the real file
// until its known-fail was retired; the composition is pinned here so a
// future entry of that shape cannot regress).

TEST_F(SpecInventoryMergeTest, ExpectOverridesLoadFromOverridesJson) {
    const auto primary = writeTemp("primary.json", kPrimary);
    const auto ov = writeTemp("ov.json", R"({
      "overrides": {
        "ARP_07": {
          "expect_overrides": ["eventgroup_id=0x0002"],
          "expect_overrides_ref": "dut/env/expect_overrides.md"
        }
      }
    })");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {}, ov.string(), &err);
    ASSERT_TRUE(inv.has_value()) << err;

    const auto *sc = inv->find(kDefaultSuite, "ARP_07");
    ASSERT_NE(sc, nullptr);
    ASSERT_EQ(sc->expect_overrides.size(), 1u);
    EXPECT_EQ(sc->expect_overrides[0], "eventgroup_id=0x0002");
    EXPECT_EQ(sc->expect_overrides_ref, "dut/env/expect_overrides.md");

    // A case with no entry keeps an EMPTY vector — runCase appends nothing,
    // so the driver's surface passes through untouched.
    const auto *other = inv->find(kDefaultSuite, "IPV4_HEADER_05");
    ASSERT_NE(other, nullptr);
    EXPECT_TRUE(other->expect_overrides.empty());
}

TEST_F(SpecInventoryMergeTest, ExpectOverridesCoexistWithPlatformKnownFail) {
    const auto primary = writeTemp("primary.json", kPrimary);
    const auto ov = writeTemp("ov.json", R"({
      "overrides": {
        "ARP_07": {
          "platform_known_fail": true,
          "platform_known_fail_ref": "memory/some_note.md",
          "expect_overrides": ["eventgroup_id=0x0005"]
        }
      }
    })");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {}, ov.string(), &err);
    ASSERT_TRUE(inv.has_value()) << err;

    const auto *sc = inv->find(kDefaultSuite, "ARP_07");
    ASSERT_NE(sc, nullptr);
    EXPECT_TRUE(sc->platform_known_fail);
    EXPECT_EQ(sc->platform_known_fail_ref, "memory/some_note.md");
    ASSERT_EQ(sc->expect_overrides.size(), 1u);
    EXPECT_EQ(sc->expect_overrides[0], "eventgroup_id=0x0005");
}

TEST_F(SpecInventoryMergeTest, ExpectOverridesReadsEveryArrayElementInOrder) {
    const auto primary = writeTemp("primary.json", kPrimary);
    // Order is load-bearing: runCase appends the array as-is and --expect is
    // last-wins, so a multi-token array's own last element must win.
    const auto ov = writeTemp("ov.json", R"({
      "overrides": {
        "ARP_07": { "expect_overrides": ["a=1", "b=2", "a=3"] }
      }
    })");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {}, ov.string(), &err);
    ASSERT_TRUE(inv.has_value()) << err;

    const auto *sc = inv->find(kDefaultSuite, "ARP_07");
    ASSERT_NE(sc, nullptr);
    EXPECT_EQ(sc->expect_overrides, (std::vector<std::string>{"a=1", "b=2", "a=3"}));
}

// --- suite identity -------------------------------------------------------
//
// A case's identity is (suite, id) in the registry, and every axis the
// inventory carries must resolve on the same pair. An injected suite reusing a
// literal spec id is a different test: inheriting the in-tree entry would change
// its stimulus, provision its DUT for another case and excuse its failure.

// One in-tree case carrying EVERY axis the overrides file can set, so a lookup
// that leaks any of them across a suite boundary is caught by one assertion.
constexpr const char *kTc8WithOptions11 = R"({
  "cases": [
    {"case_id": "SOMEIPSRV_OPTIONS_11", "section": "5.1.5.4", "split": "p9", "line": 3}
  ]
})";

constexpr const char *kEveryAxisOverride = R"({
  "overrides": {
    "SOMEIPSRV_OPTIONS_11": {
      "expected": false,
      "reason": "deferred for the test",
      "platform_known_fail": true,
      "platform_known_fail_ref": "docs/tech-debt.md",
      "timing_serial": true,
      "requires_secondary_iface": true,
      "expect_overrides": ["eventgroup_id=0x0002"],
      "neg_wrong_token": "service_id=0x0001",
      "neg_expect_fail": "fail:wrong_service",
      "vsomeip_cfg": "alt.json",
      "vsomeip_env": ["TC8_DUT_X=1"]
    }
  }
})";

TEST_F(SpecInventoryMergeTest, SameIdInAnotherSuiteResolvesNoInTreeAxis) {
    const auto primary = writeTemp("primary.json", kTc8WithOptions11);
    const auto ov = writeTemp("ov.json", kEveryAxisOverride);
    // The demo suite's own catalog, holding a case with the SAME literal id.
    const auto demo = writeTemp("demo.json", R"({
      "suite": "demo",
      "cases": [ {"case_id": "SOMEIPSRV_OPTIONS_11", "section": "D.1"} ]
    })");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {demo.string()}, ov.string(), &err);
    ASSERT_TRUE(inv.has_value()) << err;  // same id across suites is no collision
    EXPECT_EQ(inv->cases().size(), 2u);

    const auto *tc8 = inv->find(kDefaultSuite, "SOMEIPSRV_OPTIONS_11");
    ASSERT_NE(tc8, nullptr);
    EXPECT_FALSE(tc8->expected);
    EXPECT_TRUE(tc8->platform_known_fail);
    EXPECT_EQ(tc8->neg_wrong_token, "service_id=0x0001");

    const auto *mine = inv->find("demo", "SOMEIPSRV_OPTIONS_11");
    ASSERT_NE(mine, nullptr);
    ASSERT_NE(mine, tc8);
    EXPECT_EQ(mine->suite, "demo");
    EXPECT_EQ(mine->section, "D.1");
    EXPECT_TRUE(mine->expected);
    EXPECT_TRUE(mine->defer_reason.empty());
    EXPECT_FALSE(mine->platform_known_fail);
    EXPECT_TRUE(mine->platform_known_fail_ref.empty());
    EXPECT_FALSE(mine->timing_serial);
    EXPECT_FALSE(mine->requires_secondary_iface);
    EXPECT_TRUE(mine->expect_overrides.empty());
    EXPECT_TRUE(mine->neg_wrong_token.empty());
    EXPECT_TRUE(mine->neg_expect_fail.empty());
    EXPECT_TRUE(mine->vsomeip_cfg.empty());
    EXPECT_TRUE(mine->vsomeip_env.empty());
}

TEST_F(SpecInventoryMergeTest, SuiteWithoutItsOwnInventoryResolvesNothing) {
    // The registered demo case has no catalog of its own: it must resolve to
    // nothing at all, not fall back to the in-tree entry of the same id.
    const auto primary = writeTemp("primary.json", kTc8WithOptions11);
    const auto ov = writeTemp("ov.json", kEveryAxisOverride);

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {}, ov.string(), &err);
    ASSERT_TRUE(inv.has_value()) << err;
    EXPECT_NE(inv->find(kDefaultSuite, "SOMEIPSRV_OPTIONS_11"), nullptr);
    EXPECT_EQ(inv->find("demo", "SOMEIPSRV_OPTIONS_11"), nullptr);
    EXPECT_TRUE(inv->hasSuite(kDefaultSuite));
    EXPECT_FALSE(inv->hasSuite("demo"));
}

TEST_F(SpecInventoryMergeTest, QualifiedOverrideKeyAddressesOnlyItsSuite) {
    const auto primary = writeTemp("primary.json", kTc8WithOptions11);
    const auto demo = writeTemp("demo.json", R"({
      "suite": "DEMO",
      "cases": [ {"case_id": "someipsrv_options_11"} ]
    })");
    // Suite and id both compared case-insensitively, as the registry does.
    const auto ov = writeTemp("ov.json", R"({
      "overrides": {
        "Demo:SOMEIPSRV_OPTIONS_11": { "expect_overrides": ["ttl=3"] }
      }
    })");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {demo.string()}, ov.string(), &err);
    ASSERT_TRUE(inv.has_value()) << err;
    const auto *mine = inv->find("demo", "SOMEIPSRV_OPTIONS_11");
    ASSERT_NE(mine, nullptr);
    EXPECT_EQ(mine->expect_overrides, (std::vector<std::string>{"ttl=3"}));
    const auto *tc8 = inv->find(kDefaultSuite, "SOMEIPSRV_OPTIONS_11");
    ASSERT_NE(tc8, nullptr);
    EXPECT_TRUE(tc8->expect_overrides.empty());
}

TEST_F(SpecInventoryMergeTest, UnnamedExtraBelongsToTheInTreeSuite) {
    // An extra file with no root "suite" is the in-tree suite's, as an empty
    // TC8_EXTRA_CASE_SUITES entry is — and a "suite" inside a case block is
    // not the file's.
    const auto primary = writeTemp("primary.json", kPrimary);
    const auto extra = writeTemp("extra.json", R"({
      "cases": [ {"case_id": "OEMX_DEMO_01", "suite": "demo"} ]
    })");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {extra.string()}, "", &err);
    ASSERT_TRUE(inv.has_value()) << err;
    EXPECT_NE(inv->find(kDefaultSuite, "OEMX_DEMO_01"), nullptr);
    EXPECT_EQ(inv->find("demo", "OEMX_DEMO_01"), nullptr);
    EXPECT_FALSE(inv->hasSuite("demo"));
}

// TD-39: naming the vsomeip axis with empty values is a DECLARATION (the base
// DUT), and must be distinguishable from not naming it at all.
TEST_F(SpecInventoryMergeTest, EmptyVsomeipAxisIsADeclarationNotAnAbsence) {
    const auto primary = writeTemp("primary.json", kTc8WithOptions11);
    const auto demo = writeTemp("demo.json", R"({
      "suite": "demo",
      "cases": [ {"case_id": "SOMEIPSRV_OPTIONS_11"}, {"case_id": "SOMEIPSRV_OPTIONS_12"} ]
    })");
    const auto ov = writeTemp("ov.json", R"({
      "overrides": {
        "SOMEIPSRV_OPTIONS_11": { "vsomeip_cfg": "alt.json", "vsomeip_env": ["TC8_DUT_X=1"] },
        "demo:SOMEIPSRV_OPTIONS_11": { "vsomeip_cfg": "", "vsomeip_env": [] },
        "demo:SOMEIPSRV_OPTIONS_12": { "timing_serial": true }
      }
    })");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {demo.string()}, ov.string(), &err);
    ASSERT_TRUE(inv.has_value()) << err;

    const auto *tc8 = inv->find(kDefaultSuite, "SOMEIPSRV_OPTIONS_11");
    ASSERT_NE(tc8, nullptr);
    EXPECT_TRUE(tc8->vsomeip_declared);

    const auto *base = inv->find("demo", "SOMEIPSRV_OPTIONS_11");
    ASSERT_NE(base, nullptr);
    EXPECT_TRUE(base->vsomeip_declared);  // declared, with empty values: the base DUT
    EXPECT_TRUE(base->vsomeip_cfg.empty());
    EXPECT_TRUE(base->vsomeip_env.empty());

    const auto *silent = inv->find("demo", "SOMEIPSRV_OPTIONS_12");
    ASSERT_NE(silent, nullptr);
    EXPECT_FALSE(silent->vsomeip_declared);  // an entry, but not for this axis
}

TEST_F(SpecInventoryMergeTest, CollisionWithinOneInjectedSuiteIsLoudError) {
    const auto primary = writeTemp("primary.json", kPrimary);
    const auto a = writeTemp("a.json", R"({"suite":"demo","cases":[{"case_id":"ARP_07"}]})");
    const auto b = writeTemp("b.json", R"({"suite":"demo","cases":[{"case_id":"arp_07"}]})");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {a.string(), b.string()}, "", &err);
    EXPECT_FALSE(inv.has_value());
    EXPECT_NE(err.find("demo:arp_07"), std::string::npos) << err;
}

TEST_F(SpecInventoryMergeTest, PrimaryClaimingAnotherSuiteIsError) {
    const auto primary = writeTemp("primary.json", R"({"suite":"demo","cases":[{"case_id":"ARP_07"}]})");

    std::string err;
    auto inv = SpecInventory::load(primary.string(), {}, "", &err);
    EXPECT_FALSE(inv.has_value());
    EXPECT_NE(err.find("primary inventory"), std::string::npos) << err;
}

TEST_F(SpecInventoryMergeTest, MalformedSuiteNameIsError) {
    const auto primary = writeTemp("primary.json", kPrimary);
    const auto extra = writeTemp("extra.json", R"({"suite":"de-mo","cases":[{"case_id":"X_01"}]})");
    const auto ov = writeTemp("ov.json", R"({"overrides":{"9x:ARP_07":{"timing_serial":true}}})");

    std::string err;
    EXPECT_FALSE(SpecInventory::load(primary.string(), {extra.string()}, "", &err).has_value());
    EXPECT_NE(err.find("not a valid suite name"), std::string::npos) << err;

    err.clear();
    EXPECT_FALSE(SpecInventory::load(primary.string(), {}, ov.string(), &err).has_value());
    EXPECT_NE(err.find("invalid suite name"), std::string::npos) << err;
}

}  // namespace
