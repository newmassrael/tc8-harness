// Unit tests for the SpecInventory loader's D5 out-of-tree injection hook
// (--inventory-extra). Pins the merge-into-one-canonical-map behaviour,
// the loud-error-on-collision policy, and back-compat of the 3-arg load.
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

    EXPECT_NE(inv->find("ARP_07"), nullptr);
    EXPECT_NE(inv->find("IPV4_HEADER_05"), nullptr);  // canonical UPPER
    EXPECT_NE(inv->find("OEMX_DEMO_01"), nullptr);     // merged from extra
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
// replacing it — SOMEIP_ETS_117 is exactly that shape in the real file.

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

    const auto *sc = inv->find("ARP_07");
    ASSERT_NE(sc, nullptr);
    ASSERT_EQ(sc->expect_overrides.size(), 1u);
    EXPECT_EQ(sc->expect_overrides[0], "eventgroup_id=0x0002");
    EXPECT_EQ(sc->expect_overrides_ref, "dut/env/expect_overrides.md");

    // A case with no entry keeps an EMPTY vector — runCase appends nothing,
    // so the driver's surface passes through untouched.
    const auto *other = inv->find("IPV4_HEADER_05");
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

    const auto *sc = inv->find("ARP_07");
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

    const auto *sc = inv->find("ARP_07");
    ASSERT_NE(sc, nullptr);
    EXPECT_EQ(sc->expect_overrides, (std::vector<std::string>{"a=1", "b=2", "a=3"}));
}

}  // namespace
