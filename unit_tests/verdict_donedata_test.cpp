// Pins the conformance-verdict SSOT (verdict.h): the taxonomy mapping
// (class <-> name <-> exit code) and the donedata parser the runner uses.
//
// The runner sources each case's verdict from the SCXML `<final>`'s donedata
// (W3C SCXML 5.5), which the SCE codegen stashes via
// `DoneDataHelper::emitContentLiteral`. Because an inline `<content>` literal
// is a *string* value, the engine stashes it wrapped in one layer of JSON
// string encoding (`"{\"verdict\":...}"`). These tests feed
// `tc8::sce::verdictFromDonedata` exactly what `emitContentLiteral` produces —
// using the real SCE helper, not a hand-rolled approximation — so the encoding
// contract that regressed during the donedata-SSOT migration stays guarded.

#include <string>

#include <gtest/gtest.h>

#include "common/DoneDataHelper.h"
#include "sce_integration/verdict.h"

namespace {

using tc8::sce::Verdict;
using tc8::sce::VerdictClass;

// Mirror the generated final-state entry action: stash an authored donedata
// literal and return exactly what the engine hands back via donedataAtFinal().
std::string stash(const char *authored_literal) {
    std::string event_data;
    ::SCE::DoneDataHelper::emitContentLiteral(authored_literal, event_data);
    return event_data;
}

}  // namespace

// ---- taxonomy SSOT ---------------------------------------------------------

TEST(VerdictTaxonomy, NameAndExitCodePerClass) {
    EXPECT_EQ(tc8::sce::verdictClassName(VerdictClass::Pass), "pass");
    EXPECT_EQ(tc8::sce::verdictClassName(VerdictClass::Fail), "fail");
    EXPECT_EQ(tc8::sce::verdictClassName(VerdictClass::Inconclusive), "inconclusive");
    EXPECT_EQ(tc8::sce::verdictClassName(VerdictClass::Error), "error");
    EXPECT_EQ(tc8::sce::verdictClassName(VerdictClass::Running), "running");

    EXPECT_EQ(tc8::sce::verdictExitCode(VerdictClass::Pass), 0);
    EXPECT_EQ(tc8::sce::verdictExitCode(VerdictClass::Fail), 1);
    EXPECT_EQ(tc8::sce::verdictExitCode(VerdictClass::Inconclusive), 2);
    EXPECT_EQ(tc8::sce::verdictExitCode(VerdictClass::Error), 3);
    EXPECT_EQ(tc8::sce::verdictExitCode(VerdictClass::Running), 1);  // fail-closed
}

TEST(VerdictTaxonomy, NameRoundTripsAndUnknownIsFailClosed) {
    for (auto c : {VerdictClass::Pass, VerdictClass::Fail, VerdictClass::Inconclusive,
                   VerdictClass::Error, VerdictClass::Running}) {
        EXPECT_EQ(tc8::sce::verdictClassFromName(tc8::sce::verdictClassName(c)), c);
    }
    EXPECT_EQ(tc8::sce::verdictClassFromName("bogus"), VerdictClass::Fail);
    EXPECT_EQ(tc8::sce::verdictClassFromName(""), VerdictClass::Fail);
}

TEST(VerdictTaxonomy, StrJoinsClassAndReason) {
    EXPECT_EQ((Verdict{VerdictClass::Pass, {}}).str(), "pass");
    EXPECT_EQ((Verdict{VerdictClass::Fail, "boom"}).str(), "fail:boom");
}

// ---- donedata parsing against the real SCE encoding ------------------------

TEST(VerdictFromDonedata, PassCarriesNoReason) {
    const Verdict v = tc8::sce::verdictFromDonedata(stash(R"({"verdict":"pass"})"));
    EXPECT_EQ(v.cls, VerdictClass::Pass);
    EXPECT_EQ(v.reason, "");
    EXPECT_EQ(v.str(), "pass");
}

TEST(VerdictFromDonedata, FailJoinsClassAndReason) {
    const Verdict v = tc8::sce::verdictFromDonedata(
        stash(R"({"verdict":"fail","reason":"session_id_wrapped_to_zero"})"));
    EXPECT_EQ(v.cls, VerdictClass::Fail);
    EXPECT_EQ(v.str(), "fail:session_id_wrapped_to_zero");
}

TEST(VerdictFromDonedata, InconclusiveAndErrorClassesRoundTrip) {
    EXPECT_EQ(tc8::sce::verdictFromDonedata(
                  stash(R"({"verdict":"inconclusive","reason":"sd_emission_stalled"})"))
                  .cls,
              VerdictClass::Inconclusive);
    EXPECT_EQ(tc8::sce::verdictFromDonedata(
                  stash(R"({"verdict":"error","reason":"no_offer_service_within_listen_window"})"))
                  .cls,
              VerdictClass::Error);
}

TEST(VerdictFromDonedata, EmptyDonedataIsRunningSentinel) {
    // A non-final state, or a final without donedata, leaves the engine stash
    // empty; the runner reports the Running sentinel (exit 1, fail-closed) so
    // test_command.cpp's not-done override stays in control.
    EXPECT_EQ(tc8::sce::verdictFromDonedata("").cls, VerdictClass::Running);
}

TEST(VerdictFromDonedata, ParsesBareObjectWithoutStringWrapper) {
    // Encoding-agnostic: a donedata already presented as a bare JSON object
    // must parse identically to the string-wrapped form.
    EXPECT_EQ(tc8::sce::verdictFromDonedata(R"({"verdict":"pass"})").cls, VerdictClass::Pass);
    EXPECT_EQ(tc8::sce::verdictFromDonedata(R"({"verdict":"fail","reason":"x"})").str(),
              "fail:x");
}

TEST(VerdictDonedataHelpers, JsonStringFieldHandlesAbsentKey) {
    EXPECT_EQ(tc8::sce::jsonStringField(R"({"verdict":"pass"})", "reason"), "");
    EXPECT_EQ(tc8::sce::jsonStringField(R"({"verdict":"pass"})", "verdict"), "pass");
}
