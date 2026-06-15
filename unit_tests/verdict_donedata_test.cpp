// Pins the conformance-verdict SSOT path: the runner sources each case's
// verdict from the SCXML `<final>`'s donedata (W3C SCXML 5.5), which the SCE
// codegen stashes via `DoneDataHelper::emitContentLiteral`. Because an inline
// `<content>` literal is a *string* value, the engine stashes it wrapped in
// one layer of JSON string encoding (`"{\"verdict\":...}"`). These tests feed
// `tc8::sce::verdictFromDonedata` exactly what `emitContentLiteral` produces,
// so they guard the encoding contract that regressed when the verdict source
// moved off the legacy `verdictFor` switch — using the real SCE helper, not a
// hand-rolled approximation, so a future change to that encoding fails here.

#include <optional>
#include <string>

#include <gtest/gtest.h>

#include "common/DoneDataHelper.h"
#include "sce_integration/test_runner.h"

namespace {

// Mirror the generated final-state entry action: stash an authored donedata
// literal and return exactly what the engine would hand back via
// `donedataAtFinal()`.
std::string stash(const char *authored_literal) {
    std::string event_data;
    ::SCE::DoneDataHelper::emitContentLiteral(authored_literal, event_data);
    return event_data;
}

}  // namespace

TEST(VerdictFromDonedata, PassCarriesNoReason) {
    EXPECT_EQ(tc8::sce::verdictFromDonedata(stash(R"({"verdict":"pass"})")), "pass");
}

TEST(VerdictFromDonedata, FailJoinsClassAndReasonWithColon) {
    EXPECT_EQ(
        tc8::sce::verdictFromDonedata(
            stash(R"({"verdict":"fail","reason":"session_id_wrapped_to_zero"})")),
        "fail:session_id_wrapped_to_zero");
}

TEST(VerdictFromDonedata, InconclusiveAndErrorClassesRoundTrip) {
    EXPECT_EQ(
        tc8::sce::verdictFromDonedata(
            stash(R"({"verdict":"inconclusive","reason":"sd_emission_stalled"})")),
        "inconclusive:sd_emission_stalled");
    EXPECT_EQ(
        tc8::sce::verdictFromDonedata(
            stash(R"({"verdict":"error","reason":"no_offer_service_within_listen_window"})")),
        "error:no_offer_service_within_listen_window");
}

TEST(VerdictFromDonedata, EmptyDonedataIsRunningSentinel) {
    // A non-final state, or a final without donedata, leaves the engine stash
    // empty; the runner reports the "running" sentinel (the old verdictFor
    // default arm) so test_command.cpp's not-done override stays in control.
    EXPECT_EQ(tc8::sce::verdictFromDonedata(""), "running");
}

TEST(VerdictFromDonedata, ParsesBareObjectWithoutStringWrapper) {
    // Encoding-agnostic: a donedata already presented as a bare JSON object
    // (e.g. a future `<param>`-based final) must parse identically.
    EXPECT_EQ(tc8::sce::verdictFromDonedata(R"({"verdict":"pass"})"), "pass");
    EXPECT_EQ(tc8::sce::verdictFromDonedata(R"({"verdict":"fail","reason":"x"})"),
              "fail:x");
}

TEST(VerdictDonedataHelpers, JsonStringFieldHandlesAbsentKey) {
    EXPECT_EQ(tc8::sce::jsonStringField(R"({"verdict":"pass"})", "reason"), "");
    EXPECT_EQ(tc8::sce::jsonStringField(R"({"verdict":"pass"})", "verdict"), "pass");
}
