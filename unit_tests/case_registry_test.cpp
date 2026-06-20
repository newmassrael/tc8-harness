#include <gtest/gtest.h>

#include <memory>
#include <string_view>
#include <vector>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"

namespace tc8::sce {
namespace {

// Minimal test-only runner; the registry factory only cares about the
// ITestRunner contract, not the underlying state machine.
class DummyRunner : public ITestRunner {
public:
    void kickStimulus(std::string_view, IDutControl &) override {}

    void start() override {}

    void onCaptured(const ::tc8::CapturedEvent &) override {}

    void tick() override {}

    bool isDone() const override {
        return true;
    }

    ::tc8::sce::Verdict verdict() const override {
        return ::tc8::sce::Verdict{::tc8::sce::VerdictClass::Pass, {}};
    }

    void setNextPcapFrameIdx(int /*idx*/) override {}

    std::string dumpTraceJson() const override {
        return "{\"schema_version\":1,\"steps\":[]}";
    }
};

CaseEntry makeEntry(std::string_view id, bool deprecated = false) {
    return CaseEntry{
        id, deriveCategory(id), "0.0", "desc", deprecated, 1, ::tc8::BpfGroup::SomeIp,
        /*bpf_expression=*/{}, /*required_capabilities=*/0U, [](const ::tc8::TestConfig &) {
            return std::unique_ptr<ITestRunner>(new DummyRunner());
        }};
}

TEST(IsWellFormedCaseId, AcceptsRealTc8Ids) {
    EXPECT_TRUE(isWellFormedCaseId("SOMEIPSRV_FORMAT_01"));
    EXPECT_TRUE(isWellFormedCaseId("ARP_49"));
    EXPECT_TRUE(isWellFormedCaseId("SOMEIP_ETS_025"));
    EXPECT_TRUE(isWellFormedCaseId("TCP_BASICS_15"));
    EXPECT_TRUE(isWellFormedCaseId("TCP_AVOIDANCE_1"));
    EXPECT_TRUE(isWellFormedCaseId("UDP_MessageFormat_01"));
}

TEST(IsWellFormedCaseId, AcceptsKnownVariantTags) {
    // §4.5.6.2 fault-injection negatives — the _NEG variant pairs
    // with a positive case under the same category.
    EXPECT_TRUE(isWellFormedCaseId("IPV4_AUTOCONF_ADDRESS_SELECTION_06_NEG"));
    EXPECT_TRUE(isWellFormedCaseId("ARP_49_NEG"));
    // Multi-guard cases carry one _NEG<n> variant per fail-final.
    EXPECT_TRUE(isWellFormedCaseId("IPV4_AUTOCONF_NETWORK_PARTITIONS_01_NEG2"));
    EXPECT_TRUE(isWellFormedCaseId("IPV4_AUTOCONF_ADDRESS_SELECTION_15_NEG4"));
}

TEST(IsWellFormedCaseId, RejectsMalformedIds) {
    EXPECT_FALSE(isWellFormedCaseId(""));
    EXPECT_FALSE(isWellFormedCaseId("ARP"));
    EXPECT_FALSE(isWellFormedCaseId("ARP_"));
    EXPECT_FALSE(isWellFormedCaseId("ARP_FOO"));
    EXPECT_FALSE(isWellFormedCaseId("ARP_01X"));
    EXPECT_FALSE(isWellFormedCaseId("_01"));
    EXPECT_FALSE(isWellFormedCaseId("_NEG"));         // tag without core
    EXPECT_FALSE(isWellFormedCaseId("ARP_NEG"));      // tag but no digits
    EXPECT_FALSE(isWellFormedCaseId("ARP_FOO_NEG"));  // non-numeric core
}

TEST(DeriveCategory, ReturnsPrefixBeforeFinalNumericSuffix) {
    EXPECT_EQ(deriveCategory("SOMEIPSRV_FORMAT_01"), "SOMEIPSRV_FORMAT");
    EXPECT_EQ(deriveCategory("ARP_49"), "ARP");
    EXPECT_EQ(deriveCategory("SOMEIP_ETS_025"), "SOMEIP_ETS");
    EXPECT_EQ(deriveCategory("TCP_BASICS_15"), "TCP_BASICS");
}

TEST(DeriveCategory, IgnoresKnownVariantTag) {
    EXPECT_EQ(deriveCategory("IPV4_AUTOCONF_ADDRESS_SELECTION_06_NEG"),
              "IPV4_AUTOCONF_ADDRESS_SELECTION");
    // Positive and negative share a category — the variant tag does
    // not split the group.
    EXPECT_EQ(deriveCategory("ARP_49_NEG"), deriveCategory("ARP_49"));
    // Every _NEG<n> variant of a multi-guard case derives the same
    // category + number as the positive base.
    EXPECT_EQ(deriveCategory("IPV4_AUTOCONF_NETWORK_PARTITIONS_01_NEG2"),
              deriveCategory("IPV4_AUTOCONF_NETWORK_PARTITIONS_01"));
    EXPECT_EQ(deriveCategory("IPV4_AUTOCONF_ADDRESS_SELECTION_15_NEG4"),
              deriveCategory("IPV4_AUTOCONF_ADDRESS_SELECTION_15"));
}

TEST(CaseRegistry, AddFind) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_01"));
    reg.add(makeEntry("ARP_02"));
    EXPECT_EQ(reg.size(), 2u);

    const auto *hit = reg.find("ARP_02");
    ASSERT_NE(hit, nullptr);
    EXPECT_EQ(hit->id, "ARP_02");
    EXPECT_EQ(hit->category, "ARP");
    EXPECT_EQ(reg.find("ARP_99"), nullptr);
}

TEST(CaseRegistry, FindIsCaseInsensitive) {
    // The registered id keeps the spec's canonical notation (mixed-case
    // categories like UDP_DatagramLength_01), but a CLI arg or override
    // key may arrive in any letter case. find() resolves them all to the
    // one registered entry — matching how the inventory cross-check
    // (SpecInventory::canonicalise) already treats case IDs, so the CLI
    // and the override/--vs-spec paths never disagree on identity (P10).
    CaseRegistry reg;
    reg.add(makeEntry("UDP_DatagramLength_01"));

    for (const char *probe : {"UDP_DatagramLength_01", "UDP_DATAGRAMLENGTH_01",
                              "udp_datagramlength_01", "Udp_DatagramLength_01"}) {
        const auto *hit = reg.find(probe);
        ASSERT_NE(hit, nullptr) << "probe: " << probe;
        // The resolved entry always reports the canonical registered id,
        // never the probe's notation.
        EXPECT_EQ(hit->id, "UDP_DatagramLength_01") << "probe: " << probe;
    }
    EXPECT_EQ(reg.find("UDP_DatagramLength_02"), nullptr);
}

TEST(CaseRegistry, FindKeepsVariantTagDistinct) {
    // Case-insensitivity must not fold a negative variant onto its
    // positive sibling: the two are distinct registered cases. (This is
    // why find() uppercases rather than reusing SpecInventory::canonicalise,
    // which strips the _NEG tag to derive a shared primary key.)
    CaseRegistry reg;
    reg.add(makeEntry("IPv4_AUTOCONF_CONFLICT_06"));
    reg.add(makeEntry("IPv4_AUTOCONF_CONFLICT_06_NEG"));

    const auto *pos = reg.find("ipv4_autoconf_conflict_06");
    const auto *neg = reg.find("IPV4_AUTOCONF_CONFLICT_06_NEG");
    ASSERT_NE(pos, nullptr);
    ASSERT_NE(neg, nullptr);
    EXPECT_EQ(pos->id, "IPv4_AUTOCONF_CONFLICT_06");
    EXPECT_EQ(neg->id, "IPv4_AUTOCONF_CONFLICT_06_NEG");
    EXPECT_NE(pos, neg);
}

TEST(CaseRegistryDeathTest, AddRejectsCaseInsensitiveCollision) {
    // find() resolves case-insensitively, so two ids equal under ASCII
    // case would make resolution ambiguous (first-wins). add() rejects
    // the collision at registration — the registry's canonical-uniqueness
    // invariant fails loud and early, before main().
    CaseRegistry reg;
    reg.add(makeEntry("UDP_Padding_02"));
    EXPECT_DEATH(reg.add(makeEntry("UDP_PADDING_02")),
                 "duplicate case registration");
}

TEST(CaseRegistry, ListSortedByCategoryThenNumericSuffix) {
    CaseRegistry reg;
    // Insert intentionally out of order, and include a numeric suffix
    // that would sort incorrectly under lexicographic order (10 before 2).
    reg.add(makeEntry("ARP_10"));
    reg.add(makeEntry("SOMEIP_ETS_025"));
    reg.add(makeEntry("ARP_02"));
    reg.add(makeEntry("SOMEIPSRV_FORMAT_01"));
    reg.add(makeEntry("SOMEIP_ETS_003"));

    const auto ordered = reg.listSorted();
    ASSERT_EQ(ordered.size(), 5u);
    EXPECT_EQ(ordered[0]->id, "ARP_02");
    EXPECT_EQ(ordered[1]->id, "ARP_10");
    EXPECT_EQ(ordered[2]->id, "SOMEIPSRV_FORMAT_01");
    EXPECT_EQ(ordered[3]->id, "SOMEIP_ETS_003");
    EXPECT_EQ(ordered[4]->id, "SOMEIP_ETS_025");
}

TEST(CaseRegistry, ListSortedKeepsVariantTagAdjacentToPositive) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_05_NEG"));
    reg.add(makeEntry("ARP_06"));
    reg.add(makeEntry("ARP_05"));
    reg.add(makeEntry("ARP_06_NEG"));

    const auto ordered = reg.listSorted();
    ASSERT_EQ(ordered.size(), 4u);
    // Tie-break on the full id places the bare positive before its
    // variant within the same (category, number) group — a stable
    // adjacency that keeps the negative beside its positive in CLI
    // listings.
    EXPECT_EQ(ordered[0]->id, "ARP_05");
    EXPECT_EQ(ordered[1]->id, "ARP_05_NEG");
    EXPECT_EQ(ordered[2]->id, "ARP_06");
    EXPECT_EQ(ordered[3]->id, "ARP_06_NEG");
}

TEST(CaseRegistry, ListSortedHidesDeprecatedByDefault) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_01"));
    reg.add(makeEntry("ARP_02", /*deprecated=*/true));

    EXPECT_EQ(reg.listSorted(/*include_deprecated=*/false).size(), 1u);
    EXPECT_EQ(reg.listSorted(/*include_deprecated=*/false)[0]->id, "ARP_01");
    EXPECT_EQ(reg.listSorted(/*include_deprecated=*/true).size(), 2u);
}

TEST(CaseRegistry, FactoryProducesFreshRunner) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_01"));
    const auto *e = reg.find("ARP_01");
    ASSERT_NE(e, nullptr);

    const ::tc8::TestConfig cfg{};
    auto a = e->factory(cfg);
    auto b = e->factory(cfg);
    ASSERT_NE(a.get(), nullptr);
    ASSERT_NE(b.get(), nullptr);
    EXPECT_NE(a.get(), b.get());  // distinct instances
    EXPECT_EQ(a->verdict().str(), "pass");
}

TEST(CaseRegistryDeathTest, DuplicateIdAborts) {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    CaseRegistry reg;
    reg.add(makeEntry("ARP_01"));
    EXPECT_DEATH_IF_SUPPORTED(reg.add(makeEntry("ARP_01")), "duplicate case registration for 'ARP_01'");
}

// Out-of-tree capture-filter escape hatch: bpfExpressionOf<T>() reads the
// optional kBpfExpression member when present and yields an empty view
// otherwise, so a case without it (the overwhelming majority) registers
// with bpf_expression empty and falls back to its kBpfGroup filter.
struct TraitsWithBpfExpr {
    static constexpr std::string_view kBpfExpression = "udp port 5000";
};
struct TraitsWithoutBpfExpr {};

TEST(BpfExpression, SfinaeReadsOptionalMember) {
    EXPECT_EQ(bpfExpressionOf<TraitsWithBpfExpr>(), "udp port 5000");
    EXPECT_TRUE(bpfExpressionOf<TraitsWithoutBpfExpr>().empty());
    static_assert(has_bpf_expression_v<TraitsWithBpfExpr>);
    static_assert(!has_bpf_expression_v<TraitsWithoutBpfExpr>);
}

}  // namespace
}  // namespace tc8::sce
