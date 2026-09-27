#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
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

    void setCaptureStats(std::vector<::tc8::CaptureStats> /*stats*/) override {}

    bool finalTransitionWasFrameDriven() const override {
        return false;
    }

    std::string dumpTraceJson() const override {
        return "{\"schema_version\":2,\"capture\":[],\"steps\":[]}";
    }

    std::vector<::tc8::IPollableService *> pollableServices() override {
        return {};
    }
};

CaseEntry makeEntry(std::string_view id, bool deprecated = false) {
    return CaseEntry{
        id, deriveCategory(id), "desc", deprecated, 1, ::tc8::BpfGroup::SomeIp,
        /*bpf_expression=*/{}, /*extra_capture_udp_ports=*/nullptr,
        /*extra_capture_udp_port_count=*/0U, /*required_capabilities=*/0U,
        ControlPlaneRole::kScaffolding,
        [](const ::tc8::TestConfig &) {
            return std::unique_ptr<ITestRunner>(new DummyRunner());
        }};
}

// Same as makeEntry but in an explicit suite (the OEM-catalog axis).
CaseEntry makeEntryInSuite(std::string_view suite, std::string_view id) {
    CaseEntry e = makeEntry(id);
    e.suite = suite;
    return e;
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
    reg.add(makeEntry("ARP_01"));  // suite defaults to "tc8"
    EXPECT_DEATH_IF_SUPPORTED(reg.add(makeEntry("ARP_01")),
                              "duplicate case registration for 'tc8:ARP_01'");
}

// The suite axis: the same literal case id in two different suites coexists
// (an OEM catalog reusing in-tree spec ids), resolves via qualified find, and
// is ambiguous (nullptr) via the unqualified find.
TEST(CaseRegistry, SameIdDifferentSuitesCoexist) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_01"));                 // suite "tc8"
    reg.add(makeEntryInSuite("vendorx", "ARP_01"));  // must NOT abort
    const CaseEntry *t = reg.find("tc8", "ARP_01");
    const CaseEntry *h = reg.find("vendorx", "ARP_01");
    ASSERT_NE(t, nullptr);
    ASSERT_NE(h, nullptr);
    EXPECT_EQ(t->suite, "tc8");
    EXPECT_EQ(h->suite, "vendorx");
    EXPECT_EQ(reg.find("ARP_01"), nullptr);  // ambiguous across suites
}

TEST(CaseRegistry, FindSuiteIdNonexistentSuiteReturnsNull) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_03"));  // suite "tc8"
    EXPECT_EQ(reg.find("nosuch", "ARP_03"), nullptr);  // wrong suite
    EXPECT_NE(reg.find("tc8", "ARP_03"), nullptr);     // right suite
}

TEST(CaseRegistry, FindSuiteIdIsCaseInsensitiveOnBothAxes) {
    CaseRegistry reg;
    reg.add(makeEntryInSuite("vendorx", "SOMEIPSRV_RPC_01"));
    EXPECT_NE(reg.find("VENDORX", "someipsrv_rpc_01"), nullptr);  // suite + id both ci
    EXPECT_NE(reg.find("vendorx", "SOMEIPSRV_RPC_01"), nullptr);
}

// A duplicate within the SAME suite still aborts.
TEST(CaseRegistryDeathTest, DuplicateSuiteIdAborts) {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    CaseRegistry reg;
    reg.add(makeEntryInSuite("vendorx", "ARP_01"));
    EXPECT_DEATH_IF_SUPPORTED(reg.add(makeEntryInSuite("vendorx", "ARP_01")),
                              "duplicate case registration for 'vendorx:ARP_01'");
}

// Case aliases (case_alias.h): an injected suite's id registered as a copy of an
// in-tree case's entry, so the alias runs the target's state machine with the
// target's traits and only its identity differs.
TEST(CaseRegistryAlias, CopiesTheTargetUnderTheAliasIdentity) {
    CaseRegistry reg;
    CaseEntry target = makeEntry("TCP_BASICS_04");
    target.topology = 2;
    target.required_capabilities = 0x20U;
    target.bpf_group = ::tc8::BpfGroup::Tcp;
    reg.add(std::move(target));

    std::string err;
    ASSERT_TRUE(reg.addAlias({"vendorx", "VX_TCP_04", "tc8", "tcp_basics_04"}, &err)) << err;

    const CaseEntry *a = reg.find("vendorx", "VX_TCP_04");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(a->suite, "vendorx");
    EXPECT_EQ(a->id, "VX_TCP_04");
    // Category follows the alias's OWN id, as every listing groups by it.
    EXPECT_EQ(a->category, "VX_TCP");
    ASSERT_TRUE(a->isAlias());
    EXPECT_EQ(a->alias_of.suite, "tc8");
    // The target's registered spelling, not the declaration's.
    EXPECT_EQ(a->alias_of.id, "TCP_BASICS_04");
    // Everything that decides how the case runs is the target's.
    EXPECT_EQ(a->topology, 2);
    EXPECT_EQ(a->required_capabilities, 0x20U);
    EXPECT_EQ(a->bpf_group, ::tc8::BpfGroup::Tcp);
    ASSERT_TRUE(static_cast<bool>(a->factory));
    EXPECT_EQ(a->factory(::tc8::TestConfig{})->verdict().str(), "pass");

    // The target is untouched and not itself an alias.
    const CaseEntry *t = reg.find("tc8", "TCP_BASICS_04");
    ASSERT_NE(t, nullptr);
    EXPECT_FALSE(t->isAlias());
    EXPECT_EQ(reg.size(), 2U);
}

TEST(CaseRegistryAlias, RefusesAMissingTarget) {
    CaseRegistry reg;
    std::string err;
    EXPECT_FALSE(reg.addAlias({"vendorx", "VX_ARP_03", "tc8", "ARP_03"}, &err));
    EXPECT_NE(err.find("not a registered case"), std::string::npos) << err;
    EXPECT_EQ(reg.size(), 0U);
}

TEST(CaseRegistryAlias, RefusesAnAliasOfAnAlias) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_03"));
    std::string err;
    ASSERT_TRUE(reg.addAlias({"vendorx", "VX_ARP_03", "tc8", "ARP_03"}, &err)) << err;
    EXPECT_FALSE(reg.addAlias({"vendory", "VY_ARP_03", "vendorx", "VX_ARP_03"}, &err));
    EXPECT_NE(err.find("itself an alias"), std::string::npos) << err;
}

// One test under two ids in one catalog would be counted twice by that
// catalog's coverage report, so an alias must cross a suite boundary.
TEST(CaseRegistryAlias, RefusesTheTargetsOwnSuite) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_03"));
    std::string err;
    EXPECT_FALSE(reg.addAlias({"TC8", "ARP_99", "tc8", "ARP_03"}, &err));
    EXPECT_NE(err.find("different suite"), std::string::npos) << err;
}

TEST(CaseRegistryAlias, RefusesATakenIdentity) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_03"));
    reg.add(makeEntryInSuite("vendorx", "ARP_03"));
    std::string err;
    EXPECT_FALSE(reg.addAlias({"vendorx", "arp_03", "tc8", "ARP_03"}, &err));
    EXPECT_NE(err.find("already registered"), std::string::npos) << err;
}

TEST(CaseRegistryAlias, RefusesAMalformedAliasId) {
    CaseRegistry reg;
    reg.add(makeEntry("ARP_03"));
    std::string err;
    EXPECT_FALSE(reg.addAlias({"vendorx", "VX_ARP", "tc8", "ARP_03"}, &err));
    EXPECT_NE(err.find("_<digits>"), std::string::npos) << err;
}

// The stimulus-marker opt-in (tc8/stimulus_marker.h) is detected from the hook's
// signature alone, keyed on the state-machine type — a case declares
// `onStimulusApplied(Captured&, SM&, std::string_view)` and nothing else.
struct MarkerAwareSM {};
struct MarkerBlindSM {};

}  // namespace

template <> struct TestCaseTraits<MarkerAwareSM> {
    struct Captured {};
    static void onStimulusApplied(Captured &, MarkerAwareSM &, std::string_view) {}
};
template <> struct TestCaseTraits<MarkerBlindSM> {
    struct Captured {};
};

namespace {

static_assert(has_stimulus_applied_hook_v<MarkerAwareSM>,
              "a case declaring onStimulusApplied must be detected as observing markers");
static_assert(!has_stimulus_applied_hook_v<MarkerBlindSM>,
              "a case without the hook must not be");

// The §4.2 UDP-observing cases grade only the egress provocation's own datagram.
// Measured on a DUT with its own service traffic: a SOME/IP event datagram to the
// tester, carrying the same learned Ethernet destination, met the guard first.
TEST(ArpEgressProvocation, OnlyTheProvokedDatagramIsTheEgressUnderTest) {
    ::tc8::UdpFrame provoked{};
    provoked.src_port = ::tc8::stimulus::kEgressBootDutSrcPort;
    provoked.dst_port = ::tc8::ut::kDataPort;
    EXPECT_TRUE(isEgressProvocationDatagram(provoked));

    ::tc8::UdpFrame service_event{};  // 172.16.0.2.51712 > 172.16.0.1.51916
    service_event.src_port = 51712;
    service_event.dst_port = 51916;
    EXPECT_FALSE(isEgressProvocationDatagram(service_event));

    // The pair, not either half: a reply INTO the provocation's source port, or a
    // datagram to the data port from elsewhere, is not the provoked one.
    ::tc8::UdpFrame swapped = provoked;
    std::swap(swapped.src_port, swapped.dst_port);
    EXPECT_FALSE(isEgressProvocationDatagram(swapped));
    ::tc8::UdpFrame other_src = provoked;
    other_src.src_port = 30600;
    EXPECT_FALSE(isEgressProvocationDatagram(other_src));
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
