// The absence hypotheses (docs/verdict_policy.md §2.1): which verdicts claim an
// absence, how H2 and H1 downgrade them, and which liveness anchor a case may use.

#include <gtest/gtest.h>

#include "sce_integration/absence_qualification.h"
#include "sce_integration/dut_requirements.h"

namespace {

using ::tc8::sce::AbsenceFacts;
using ::tc8::sce::claimsAbsence;
using ::tc8::sce::defaultRequirementsUnderTest;
using ::tc8::sce::DutRequirement;
using ::tc8::sce::DutRequirements;
using ::tc8::sce::LivenessAnchorKind;
using ::tc8::sce::LivenessAnchorOutcome;
using ::tc8::sce::needsLivenessAnchor;
using ::tc8::sce::qualifyAbsence;
using ::tc8::sce::selectLivenessAnchor;
using ::tc8::sce::Verdict;
using ::tc8::sce::VerdictClass;

const Verdict kPass{VerdictClass::Pass, {}, {}};
const Verdict kQuiescence{VerdictClass::Fail, "no_dut_arp_reply", "observed_quiescence"};
const Verdict kInert{VerdictClass::Fail, "dut_silent_despite_flavor", "fault_injection_inert"};
const Verdict kValueFail{VerdictClass::Fail, "phase1_rto_below_doubled_baseline", "observed_violation"};
const Verdict kInconclusive{VerdictClass::Inconclusive, "no_reply", "property_unobserved"};

AbsenceFacts wholeCapture(LivenessAnchorOutcome anchor) {
    return AbsenceFacts{/*frame_decided=*/false, /*capture_whole=*/true, {}, anchor};
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

TEST(QualifyAbsence, AnAnsweredAnchorOverAWholeCaptureKeepsTheVerdict) {
    EXPECT_EQ(qualifyAbsence(kQuiescence, wholeCapture(LivenessAnchorOutcome::kAnswered)).str(),
              "fail:no_dut_arp_reply");
    EXPECT_EQ(qualifyAbsence(kPass, wholeCapture(LivenessAnchorOutcome::kAnswered)).str(), "pass");
}

TEST(QualifyAbsence, AnIncompleteCaptureDowngradesFirstAndNamesItsHole) {
    const AbsenceFacts facts{false, false, "capture_lost_frames_absence_unproven", LivenessAnchorOutcome::kAnswered};
    const Verdict v = qualifyAbsence(kQuiescence, facts);
    EXPECT_EQ(v.str(), "inconclusive:capture_lost_frames_absence_unproven");
    EXPECT_EQ(v.role, "property_unobserved");
}

TEST(QualifyAbsence, EachAnchorFailureNamesItself) {
    EXPECT_EQ(qualifyAbsence(kQuiescence, wholeCapture(LivenessAnchorOutcome::kUnanswered)).str(),
              "inconclusive:liveness_anchor_unanswered_absence_unproven");
    EXPECT_EQ(qualifyAbsence(kInert, wholeCapture(LivenessAnchorOutcome::kNoDutAddress)).str(),
              "inconclusive:liveness_anchor_no_dut_address_absence_unproven");
    EXPECT_EQ(qualifyAbsence(kPass, wholeCapture(LivenessAnchorOutcome::kUnavailable)).str(),
              "inconclusive:liveness_anchor_unavailable_absence_unproven");
}

TEST(QualifyAbsence, ASkippedAnchorIsNotEvidenceOfLiveness) {
    EXPECT_EQ(qualifyAbsence(kQuiescence, wholeCapture(LivenessAnchorOutcome::kNotRun)).str(),
              "inconclusive:liveness_anchor_unavailable_absence_unproven");
}

TEST(QualifyAbsence, VerdictsThatClaimNoAbsenceAreUntouched) {
    const AbsenceFacts nothing_holds{false, false, "capture_lost_frames_absence_unproven",
                                     LivenessAnchorOutcome::kUnanswered};
    EXPECT_EQ(qualifyAbsence(kValueFail, nothing_holds).str(), "fail:phase1_rto_below_doubled_baseline");
    EXPECT_EQ(qualifyAbsence(kInconclusive, nothing_holds).str(), "inconclusive:no_reply");
    const AbsenceFacts frame{true, false, "capture_lost_frames_absence_unproven",
                             LivenessAnchorOutcome::kNotRun};
    EXPECT_EQ(qualifyAbsence(kQuiescence, frame).str(), "fail:no_dut_arp_reply");
}

TEST(NeedsLivenessAnchor, OnlyAnAbsenceOverAWholeCapture) {
    EXPECT_TRUE(needsLivenessAnchor(kQuiescence, false, true));
    EXPECT_FALSE(needsLivenessAnchor(kQuiescence, false, false));
    EXPECT_FALSE(needsLivenessAnchor(kQuiescence, true, true));
    EXPECT_FALSE(needsLivenessAnchor(kValueFail, false, true));
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
