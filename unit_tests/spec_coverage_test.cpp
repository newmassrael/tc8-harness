// Unit tests for computeSpecCoverage — the `--list-cases --vs-spec` gap report
// as data. Pins its one-catalog-per-report scoping: with two suites registered,
// only the scoped suite's cases count against that suite's inventory, so an
// injected suite reusing a TC8 id can neither mark the TC8 spec case registered
// (the CI gate passing on a case the TC8 catalog does not register) nor surface
// among the TC8 report's registered-but-not-in-spec.
//
// Fixtures are written to unique temp paths and removed in TearDown.

#include "sce_integration/spec_coverage.h"

#include <gtest/gtest.h>

#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace tc8::sce {
namespace {

// The factory is never invoked by the coverage computation; an entry needs only
// its identity and category.
CaseEntry entryIn(std::string_view suite, std::string_view id) {
    CaseEntry e;
    e.id = id;
    e.category = deriveCategory(id);
    e.suite = suite;
    return e;
}

class SpecCoverageTest : public ::testing::Test {
protected:
    std::filesystem::path writeTemp(const std::string &name, const std::string &content) {
        const auto path = std::filesystem::temp_directory_path() /
                          ("tc8_speccov_" + std::to_string(::getpid()) + "_" + name);
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

constexpr const char *kTc8Inventory = R"({
  "cases": [
    {"case_id": "ARP_03", "section": "4.2.1"},
    {"case_id": "ARP_04", "section": "4.2.1"}
  ]
})";

const SpecCoverage::Category *categoryOf(const SpecCoverage &cov, std::string_view name) {
    for (const auto &c : cov.categories) {
        if (c.name == name) {
            return &c;
        }
    }
    return nullptr;
}

std::vector<std::string> idsOf(const std::vector<const SpecCase *> &v) {
    std::vector<std::string> out;
    for (const auto *sc : v) {
        out.push_back(sc->id);
    }
    return out;
}

TEST_F(SpecCoverageTest, InjectedSameIdCaseDoesNotMarkTheTc8CaseRegistered) {
    // Two registered suites. The in-tree suite registers ARP_04 only; the
    // injected demo suite registers its own ARP_03 plus one id of its own.
    CaseRegistry reg;
    reg.add(entryIn(kDefaultSuite, "ARP_04"));
    reg.add(entryIn("demo", "ARP_03"));
    reg.add(entryIn("demo", "DEMO_ONLY_01"));

    const auto primary = writeTemp("tc8.json", kTc8Inventory);
    std::string err;
    const auto inv = SpecInventory::load(primary.string(), {}, "", &err);
    ASSERT_TRUE(inv.has_value()) << err;

    const auto cov = computeSpecCoverage(reg, *inv, kDefaultSuite);
    ASSERT_TRUE(cov.has_value());
    const auto *arp = categoryOf(*cov, "ARP");
    ASSERT_NE(arp, nullptr);
    EXPECT_EQ(idsOf(arp->registered), (std::vector<std::string>{"ARP_04"}));
    // The TC8 spec's ARP_03 is still a gap: demo:ARP_03 is not the TC8 case.
    EXPECT_EQ(idsOf(arp->missing), (std::vector<std::string>{"ARP_03"}));
    // ...and the demo suite's own cases are not the TC8 report's business.
    EXPECT_TRUE(cov->registered_only.empty());
}

TEST_F(SpecCoverageTest, InjectedSuiteIsMeasuredAgainstItsOwnCatalog) {
    CaseRegistry reg;
    reg.add(entryIn(kDefaultSuite, "ARP_03"));
    reg.add(entryIn(kDefaultSuite, "ARP_04"));
    reg.add(entryIn("demo", "ARP_03"));
    reg.add(entryIn("demo", "DEMO_ONLY_01"));

    const auto primary = writeTemp("tc8.json", kTc8Inventory);
    const auto demo = writeTemp("demo.json", R"({
      "suite": "demo",
      "cases": [ {"case_id": "ARP_03"}, {"case_id": "ARP_05"} ]
    })");
    std::string err;
    const auto inv = SpecInventory::load(primary.string(), {demo.string()}, "", &err);
    ASSERT_TRUE(inv.has_value()) << err;

    const auto cov = computeSpecCoverage(reg, *inv, "demo");
    ASSERT_TRUE(cov.has_value());
    const auto *arp = categoryOf(*cov, "ARP");
    ASSERT_NE(arp, nullptr);
    // tc8:ARP_04 is registered, but not in demo: it counts for nothing here,
    // and demo's ARP_05 stays missing though no suite registers it.
    EXPECT_EQ(idsOf(arp->registered), (std::vector<std::string>{"ARP_03"}));
    EXPECT_EQ(idsOf(arp->missing), (std::vector<std::string>{"ARP_05"}));
    EXPECT_EQ(cov->registered_only, (std::vector<std::string>{"DEMO_ONLY_01"}));

    // The in-tree report is untouched by the demo catalog being loaded.
    const auto tc8 = computeSpecCoverage(reg, *inv, kDefaultSuite);
    ASSERT_TRUE(tc8.has_value());
    const auto *tc8_arp = categoryOf(*tc8, "ARP");
    ASSERT_NE(tc8_arp, nullptr);
    EXPECT_EQ(idsOf(tc8_arp->registered), (std::vector<std::string>{"ARP_03", "ARP_04"}));
    EXPECT_TRUE(tc8_arp->missing.empty());
}

TEST_F(SpecCoverageTest, SuiteWithNoCatalogIsRefusedNotReportedEmpty) {
    // An empty report would read as "nothing missing" — full coverage of a
    // catalog that was never loaded.
    CaseRegistry reg;
    reg.add(entryIn("demo", "ARP_03"));

    const auto primary = writeTemp("tc8.json", kTc8Inventory);
    std::string err;
    const auto inv = SpecInventory::load(primary.string(), {}, "", &err);
    ASSERT_TRUE(inv.has_value()) << err;
    EXPECT_FALSE(computeSpecCoverage(reg, *inv, "demo").has_value());
}

}  // namespace
}  // namespace tc8::sce
