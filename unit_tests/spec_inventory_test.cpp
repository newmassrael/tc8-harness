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

}  // namespace
