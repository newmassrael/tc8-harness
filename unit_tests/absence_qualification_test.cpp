// The absence hypotheses (docs/verdict_policy.md Section 2.1): which verdicts
// claim an absence, how H2, H3 and H1 downgrade them, and which liveness anchor a
// case may use.

#include <gtest/gtest.h>

#include "sce_integration/absence_qualification.h"
#include "sce_integration/dut_requirements.h"

namespace {

using ::tc8::sce::AbsenceBound;
using ::tc8::sce::AbsenceFacts;
using ::tc8::sce::claimsAbsence;
using ::tc8::sce::defaultRequirementsUnderTest;
using ::tc8::sce::DutRequirement;
using ::tc8::sce::DutRequirements;
using ::tc8::sce::LivenessAnchorKind;
using ::tc8::sce::LivenessAnchorOutcome;
using ::tc8::sce::needsLivenessAnchor;
using ::tc8::sce::qualifyAbsence;
using ::tc8::sce::resolveAbsenceBound;
using ::tc8::sce::selectLivenessAnchor;
using ::tc8::sce::Verdict;
using ::tc8::sce::VerdictClass;

const Verdict kPass{VerdictClass::Pass, {}, {}, {}};
const Verdict kQuiescence{VerdictClass::Fail, "no_dut_arp_reply", "observed_quiescence", "ParamListenTime"};
const Verdict kInert{VerdictClass::Fail, "dut_silent_despite_flavor", "fault_injection_inert", {}};
const Verdict kValueFail{VerdictClass::Fail, "phase1_rto_below_doubled_baseline", "observed_violation", {}};
const Verdict kInconclusive{VerdictClass::Inconclusive, "no_reply", "property_unobserved", {}};

constexpr std::int64_t kSecondUs = 1000 * 1000;

// A timer-decided run over a whole capture whose window covered `v`'s bound at the
// default ParamListenTime, with the anchor as given.
AbsenceFacts holdingFacts(const Verdict &v, LivenessAnchorOutcome anchor) {
    return AbsenceFacts{/*frame_decided=*/false, /*capture_whole=*/true, {}, 10 * kSecondUs,
                        resolveAbsenceBound(v.bound, ::tc8::IxitConfig{}), anchor};
}

TEST(ClaimsAbsence, TimerDecidedPassAndSilenceFailsOnly) {
    EXPECT_TRUE(claimsAbsence(kPass, false));
    EXPECT_TRUE(claimsAbsence(kQuiescence, false));
    EXPECT_TRUE(claimsAbsence(kInert, false));
    // A timer that only said when to evaluate an observed value claims nothing.
    EXPECT_FALSE(claimsAbsence(kValueFail, false));
    EXPECT_FALSE(claimsAbsence(kInconclusive, false));
}

TEST(ClaimsAbsence, AFrameDecidedVerdictCarriesItsOwnEvidence) {
    EXPECT_FALSE(claimsAbsence(kPass, true));
    EXPECT_FALSE(claimsAbsence(kQuiescence, true));
    EXPECT_FALSE(claimsAbsence(kInert, true));
}

TEST(ResolveAbsenceBound, ReadsTheIxitOrALiteral) {
    ::tc8::IxitConfig ixit;
    EXPECT_EQ(resolveAbsenceBound("ParamListenTime", ixit).us, 10 * kSecondUs);
    ixit.param_listen_time_ms = 2500;
    EXPECT_EQ(resolveAbsenceBound("ParamListenTime", ixit).us, 2500 * 1000);
    EXPECT_EQ(resolveAbsenceBound("200ms", ixit).us, 200 * 1000);
    EXPECT_EQ(resolveAbsenceBound("3s", ixit).us, 3 * kSecondUs);
    EXPECT_FALSE(resolveAbsenceBound("", ixit).declared);
    for (const char *bad : {"ParamListen", "ms", "5", "1.5s", "-3s", "10 s"}) {
        const AbsenceBound b = resolveAbsenceBound(bad, ixit);
        EXPECT_TRUE(b.declared) << bad;
        EXPECT_FALSE(b.valid) << bad;
    }
}

TEST(QualifyAbsence, EveryHypothesisHeldKeepsTheVerdict) {
    EXPECT_EQ(qualifyAbsence(kQuiescence, holdingFacts(kQuiescence, LivenessAnchorOutcome::kAnswered)).str(),
              "fail:no_dut_arp_reply");
    EXPECT_EQ(qualifyAbsence(kPass, holdingFacts(kPass, LivenessAnchorOutcome::kAnswered)).str(), "pass");
}

TEST(QualifyAbsence, AnIncompleteCaptureDowngradesFirstAndNamesItsHole) {
    AbsenceFacts facts = holdingFacts(kQuiescence, LivenessAnchorOutcome::kAnswered);
    facts.capture_whole = false;
    facts.capture_reason = "capture_lost_frames_absence_unproven";
    facts.window_us = 1;  // H3 would fail too; H2 is reported
    const Verdict v = qualifyAbsence(kQuiescence, facts);
    EXPECT_EQ(v.str(), "inconclusive:capture_lost_frames_absence_unproven");
    EXPECT_EQ(v.role, "property_unobserved");
}

TEST(QualifyAbsence, AWindowShorterThanTheBoundIsNotAnObservedSilence) {
    AbsenceFacts facts = holdingFacts(kQuiescence, LivenessAnchorOutcome::kAnswered);
    facts.window_us = 5 * kSecondUs;  // a 5 s window against the 10 s ParamListenTime
    EXPECT_EQ(qualifyAbsence(kQuiescence, facts).str(), "inconclusive:window_shorter_than_bound_absence_unproven");
    // The operator's IXIT moves the bound, not the case.
    ::tc8::IxitConfig fast;
    fast.param_listen_time_ms = 5000;
    facts.bound = resolveAbsenceBound(kQuiescence.bound, fast);
    EXPECT_EQ(qualifyAbsence(kQuiescence, facts).str(), "fail:no_dut_arp_reply");
    facts.window_us = std::nullopt;
    EXPECT_EQ(qualifyAbsence(kQuiescence, facts).str(), "inconclusive:window_shorter_than_bound_absence_unproven");
}

// A literal bound equal to its window ("within 500 ms" over a 500 ms window) reads a
// little short when measured; within the loop's resolution it still covers it.
TEST(QualifyAbsence, AWindowEqualToALiteralBoundCoversItWithinMeasurementSlack) {
    Verdict v = kQuiescence;
    v.bound = "500ms";
    AbsenceFacts facts = holdingFacts(v, LivenessAnchorOutcome::kAnswered);
    facts.window_us = 500 * 1000 - 300;  // stamped after the timer was armed
    EXPECT_EQ(qualifyAbsence(v, facts).str(), "fail:no_dut_arp_reply");
    facts.window_us = 500 * 1000 - ::tc8::sce::kWindowMeasurementSlackUs - 1;
    EXPECT_EQ(qualifyAbsence(v, facts).str(), "inconclusive:window_shorter_than_bound_absence_unproven");
}

TEST(QualifyAbsence, AQuiescenceFailMustDeclareAValidBound) {
    Verdict undeclared = kQuiescence;
    undeclared.bound.clear();
    EXPECT_EQ(qualifyAbsence(undeclared, holdingFacts(undeclared, LivenessAnchorOutcome::kAnswered)).str(),
              "inconclusive:absence_bound_undeclared_absence_unproven");
    Verdict garbled = kQuiescence;
    garbled.bound = "soon";
    EXPECT_EQ(qualifyAbsence(garbled, holdingFacts(garbled, LivenessAnchorOutcome::kAnswered)).str(),
              "inconclusive:absence_bound_unparseable_absence_unproven");
    // A pass is held to a bound only when its final declares one.
    EXPECT_EQ(qualifyAbsence(kPass, holdingFacts(kPass, LivenessAnchorOutcome::kAnswered)).str(), "pass");
}

TEST(QualifyAbsence, EachAnchorFailureNamesItself) {
    EXPECT_EQ(qualifyAbsence(kQuiescence, holdingFacts(kQuiescence, LivenessAnchorOutcome::kUnanswered)).str(),
              "inconclusive:liveness_anchor_unanswered_absence_unproven");
    EXPECT_EQ(qualifyAbsence(kInert, holdingFacts(kInert, LivenessAnchorOutcome::kNoDutAddress)).str(),
              "inconclusive:liveness_anchor_no_dut_address_absence_unproven");
    EXPECT_EQ(qualifyAbsence(kPass, holdingFacts(kPass, LivenessAnchorOutcome::kUnavailable)).str(),
              "inconclusive:liveness_anchor_unavailable_absence_unproven");
}

TEST(QualifyAbsence, ASkippedAnchorIsNotEvidenceOfLiveness) {
    EXPECT_EQ(qualifyAbsence(kQuiescence, holdingFacts(kQuiescence, LivenessAnchorOutcome::kNotRun)).str(),
              "inconclusive:liveness_anchor_unavailable_absence_unproven");
}

TEST(QualifyAbsence, VerdictsThatClaimNoAbsenceAreUntouched) {
    AbsenceFacts nothing_holds{false, false, "capture_lost_frames_absence_unproven", std::nullopt, {},
                               LivenessAnchorOutcome::kUnanswered};
    EXPECT_EQ(qualifyAbsence(kValueFail, nothing_holds).str(), "fail:phase1_rto_below_doubled_baseline");
    EXPECT_EQ(qualifyAbsence(kInconclusive, nothing_holds).str(), "inconclusive:no_reply");
    nothing_holds.frame_decided = true;
    EXPECT_EQ(qualifyAbsence(kQuiescence, nothing_holds).str(), "fail:no_dut_arp_reply");
}

TEST(NeedsLivenessAnchor, OnlyWhenTheOtherHypothesesHold) {
    AbsenceFacts facts = holdingFacts(kQuiescence, LivenessAnchorOutcome::kNotRun);
    EXPECT_TRUE(needsLivenessAnchor(kQuiescence, facts));
    facts.window_us = 1;
    EXPECT_FALSE(needsLivenessAnchor(kQuiescence, facts));
    facts = holdingFacts(kQuiescence, LivenessAnchorOutcome::kNotRun);
    facts.capture_whole = false;
    EXPECT_FALSE(needsLivenessAnchor(kQuiescence, facts));
    EXPECT_FALSE(needsLivenessAnchor(kValueFail, holdingFacts(kValueFail, LivenessAnchorOutcome::kNotRun)));
}

TEST(SelectLivenessAnchor, PrefersAnAnchorDisjointFromWhatTheCaseGrades) {
    // An IP-layer or higher case: ARP touches none of it.
    EXPECT_EQ(selectLivenessAnchor(defaultRequirementsUnderTest("TCP_BASICS_10")),
              LivenessAnchorKind::kArpExchange);
    EXPECT_EQ(selectLivenessAnchor(defaultRequirementsUnderTest("ICMPv4_TYPE_04")),
              LivenessAnchorKind::kArpExchange);
    EXPECT_EQ(selectLivenessAnchor(defaultRequirementsUnderTest("IPv4_TTL_05")),
              LivenessAnchorKind::kArpExchange);
    // A case grading the ARP responder may be anchored by an Echo, whose ARP part is
    // the resolver.
    EXPECT_EQ(selectLivenessAnchor({DutRequirement::kArpRespond}), LivenessAnchorKind::kIcmpEcho);
    // A case grading the resolver keeps the ARP exchange, which only responds.
    EXPECT_EQ(selectLivenessAnchor({DutRequirement::kArpResolve}), LivenessAnchorKind::kArpExchange);
}

// A shared requirement costs power, not soundness, so a case whose every anchor
// shares one still gets the one sharing least — ties to the ARP exchange, which
// exercises less.
TEST(SelectLivenessAnchor, AnUndeclaredArpCaseStillGetsTheLeastSharedAnchor) {
    const DutRequirements both{DutRequirement::kArpRespond, DutRequirement::kArpResolve};
    EXPECT_EQ(defaultRequirementsUnderTest("ARP_20"), both);
    EXPECT_EQ(selectLivenessAnchor(both), LivenessAnchorKind::kArpExchange);
    EXPECT_EQ(both.sharedWith(::tc8::sce::exercisedBy(LivenessAnchorKind::kArpExchange)), 1);
    // Grading everything the Echo exercises leaves the ARP exchange disjoint.
    EXPECT_EQ(selectLivenessAnchor({DutRequirement::kIpv4Receive, DutRequirement::kIcmpEchoRespond,
                                    DutRequirement::kArpResolve}),
              LivenessAnchorKind::kArpExchange);
}

TEST(DefaultRequirementsUnderTest, LinkLocalConfigurationIsNotTheIpLayer) {
    EXPECT_EQ(defaultRequirementsUnderTest("IPv4_AUTOCONF_INTRO_01"), DutRequirements{});
    EXPECT_EQ(defaultRequirementsUnderTest("IPv4_HEADER_02"), DutRequirements{DutRequirement::kIpv4Receive});
    EXPECT_EQ(defaultRequirementsUnderTest("SOMEIP_ETS_001"), DutRequirements{});
}

}  // namespace
