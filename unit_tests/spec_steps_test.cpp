// A case's own specification steps (sce_integration/spec_steps.h) and how they reach the
// live state stream: which step a transition decides, which a send performs, what the
// `spec` line says, and what is reported when a table has drifted from its machine. The
// runner wiring is pinned through the production path in run_capture_test.cpp.

#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <unistd.h>

#include "sce_integration/spec_steps.h"
#include "sce_integration/state_stream.h"
#include "stimulus/tx_observer.h"

namespace {

namespace fs = std::filesystem;
using ::tc8::sce::SpecCheck;
using ::tc8::sce::SpecProcedure;
using ::tc8::sce::SpecStep;
using ::tc8::sce::SpecTransition;
using ::tc8::stimulus::kNoSpecStep;

// The shape a case declares, with two transitions that share a trigger and differ only
// in the state they arrive at (the case that rules out keying by trigger).
constexpr SpecStep kSteps[] = {{1, "TESTER", "send the request"},
                               {2, "DUT", "answer it"},
                               {3, "TESTER", "verify"}};
constexpr SpecCheck kChecks[] = {{3, "a)", "first item"}, {3, "b)", "second item"}};
constexpr SpecTransition kRows[] = {{"", "phase2", "", 2}, {"", "pass", "", 3}};
constexpr SpecProcedure kSpec{kSteps, kChecks, kRows};

using Steps = std::vector<int>;

TEST(SpecSteps, ATransitionTakesTheStepOfTheStateItArrivesAt) {
    // Both transitions are caused by the same event; the arrival state tells them apart.
    EXPECT_EQ(::tc8::sce::specStepsForTransition(kSpec, "phase1", "phase2", "notification"),
              Steps{2});
    EXPECT_EQ(::tc8::sce::specStepsForTransition(kSpec, "phase2", "pass", "notification"),
              Steps{3});
}

TEST(SpecSteps, NoRowMeansNoStepAndNeverAGuess) {
    EXPECT_TRUE(
        ::tc8::sce::specStepsForTransition(kSpec, "phase2", "inconclusive", "deadline").empty());
    constexpr SpecProcedure none{};
    EXPECT_TRUE(::tc8::sce::specStepsForTransition(none, "a", "b", "e").empty());
}

TEST(SpecSteps, FromToAndEventAllFilter) {
    static constexpr SpecTransition rows[] = {{"a", "b", "go", 1}, {"a", "b", "stop", 2}};
    constexpr SpecProcedure spec{kSteps, {}, rows};
    EXPECT_EQ(::tc8::sce::specStepsForTransition(spec, "a", "b", "go"), Steps{1});
    EXPECT_EQ(::tc8::sce::specStepsForTransition(spec, "a", "b", "stop"), Steps{2});
    EXPECT_TRUE(::tc8::sce::specStepsForTransition(spec, "c", "b", "go").empty());
    EXPECT_TRUE(::tc8::sce::specStepsForTransition(spec, "a", "b", "other").empty());
}

TEST(SpecSteps, RowsThatNameDifferentStepsAreAllKeptAscendingAndNeverChosenBetween) {
    // One transition can be the evidence for more than one step: the case writes a row
    // for each, and the harness lists them all. Whatever order the rows come in, the
    // list is ascending.
    static constexpr SpecTransition rows[] = {{"", "pass", "", 3}, {"phase2", "pass", "", 2}};
    constexpr SpecProcedure spec{kSteps, {}, rows};
    EXPECT_EQ(::tc8::sce::specStepsForTransition(spec, "phase2", "pass", "e"), (Steps{2, 3}));
    // A row that does not match this transition adds nothing.
    EXPECT_EQ(::tc8::sce::specStepsForTransition(spec, "phase1", "pass", "e"), Steps{3});
    // Rows that agree are one step, not two: a catch-all and a specific row naming the
    // same step is how a case narrows a row, not a second step.
    static constexpr SpecTransition same[] = {{"", "pass", "", 3}, {"phase2", "pass", "", 3}};
    constexpr SpecProcedure agree{kSteps, {}, same};
    EXPECT_EQ(::tc8::sce::specStepsForTransition(agree, "phase2", "pass", "e"), Steps{3});
    // Three rows, two of them agreeing, still list each step once.
    static constexpr SpecTransition mixed[] = {
        {"", "pass", "", 3}, {"phase2", "pass", "", 1}, {"phase2", "pass", "e", 3}};
    constexpr SpecProcedure many{kSteps, {}, mixed};
    EXPECT_EQ(::tc8::sce::specStepsForTransition(many, "phase2", "pass", "e"), (Steps{1, 3}));
}

TEST(SpecSteps, ASoundTableReportsNothing) {
    EXPECT_TRUE(::tc8::sce::validateSpec(kSpec, {"phase1", "phase2", "pass"}).empty());
}

TEST(SpecSteps, ATableThatDriftedFromItsMachineSaysSo) {
    // `phase2` was renamed in the machine; the table still names the old one.
    const auto problems = ::tc8::sce::validateSpec(kSpec, {"phase1", "listening", "pass"});
    ASSERT_EQ(problems.size(), 1u);
    EXPECT_EQ(problems[0], "transitions[0]: to 'phase2' is not a state of the machine");
}

TEST(SpecSteps, UndeclaredAndRepeatedStepsAndCatchAllRowsAreReported) {
    static constexpr SpecStep steps[] = {{1, "T", "x"}, {1, "T", "y"}, {-4, "T", "z"}};
    static constexpr SpecCheck checks[] = {{9, "a)", "w"}};
    static constexpr SpecTransition rows[] = {
        {"", "pass", "", 7}, {"", "", "", 1}, {"ghost", "pass", "", 1}};
    constexpr SpecProcedure spec{steps, checks, rows};
    const auto problems = ::tc8::sce::validateSpec(spec, {"pass"});
    const std::vector<std::string> want = {
        "steps[1]: n 1 is declared twice",
        "steps[2]: n -4 is negative",
        "checks[0]: step 9 is not a declared step",
        "transitions[0]: step 7 is not a declared step",
        "transitions[1]: matches every transition",
        "transitions[2]: from 'ghost' is not a state of the machine",
    };
    EXPECT_EQ(problems, want);
}

class SpecStreamTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = fs::temp_directory_path() / ("spec_steps_test_" + std::to_string(::getpid()));
        fs::create_directories(dir_);
    }
    void TearDown() override {
        ::tc8::stimulus::setTxObserver(nullptr);
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }

    std::string path(const char *name) const { return (dir_ / name).string(); }

    static std::vector<std::string> lines(const std::string &p) {
        std::ifstream in(p);
        std::vector<std::string> out;
        for (std::string l; std::getline(in, l);) out.push_back(l);
        return out;
    }

    // The line without its sampled clock: the timestamp moves, the rest is the contract.
    static std::string withoutTime(const std::string &line) {
        const auto at = line.rfind(",\"t_us\":");
        return at == std::string::npos ? line : line.substr(0, at) + "}";
    }

    fs::path dir_;
};

TEST_F(SpecStreamTest, TheSpecLineCarriesTheCasesTextVerbatimAndEscaped) {
    const std::string p = path("spec.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);

    static constexpr SpecStep steps[] = {{1, "TESTER", "send \"echo\"\nrequest"},
                                         {2, "DUT", "\xed\x85\x8c\xec\x8a\xa4\xed\x8a\xb8"}};
    static constexpr SpecCheck checks[] = {{2, "a)", "length is 4"}};
    s->spec(SpecProcedure{steps, checks, {}});

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 2u);
    // The newline and the quote are escaped so the record stays one line; the UTF-8
    // text is passed through untouched. The harness reads none of it.
    EXPECT_EQ(withoutTime(got[1]),
              "{\"event\":\"spec\",\"steps\":[{\"n\":1,\"actor\":\"TESTER\","
              "\"text\":\"send \\\"echo\\\"\\nrequest\"},{\"n\":2,\"actor\":\"DUT\","
              "\"text\":\"\xed\x85\x8c\xec\x8a\xa4\xed\x8a\xb8\"}],"
              "\"checks\":[{\"step\":2,\"mark\":\"a)\",\"text\":\"length is 4\"}]}");
}

TEST_F(SpecStreamTest, ATableWithNoChecksStillWritesAnEmptyList) {
    const std::string p = path("nochecks.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    s->spec(SpecProcedure{kSteps, {}, {}});
    const auto got = lines(p);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_NE(got[1].find("\"checks\":[]"), std::string::npos) << got[1];
}

TEST_F(SpecStreamTest, SpecInvalidNamesEachProblem) {
    const std::string p = path("invalid.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    s->specInvalid({"transitions[0]: to 'a\"b' is not a state of the machine", "second"});
    const auto got = lines(p);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"spec_invalid","problems":["transitions[0]: to 'a\"b' is not a state )"
              R"(of the machine","second"]})");
}

TEST_F(SpecStreamTest, ATransitionForSeveralStepsListsThemAndKeepsTheFirstAsSpecStep) {
    const std::string p = path("several.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    s->transition(0, "notification", "phase1", "phase2", 4, {2, 3});
    s->transition(1, "notification", "phase2", "pass", 5, {1, 2, 7});
    // One step is the line it always was: no list for a reader that has no use for one.
    s->transition(2, "deadline", "phase2", "inconclusive", -1, {3});

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 4u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"transition","step":0,"trigger":"notification","from":"phase1",)"
              R"("to":"phase2","pcap_frame_idx":4,"spec_step":2,"spec_steps":[2,3]})");
    EXPECT_EQ(withoutTime(got[2]),
              R"({"event":"transition","step":1,"trigger":"notification","from":"phase2",)"
              R"("to":"pass","pcap_frame_idx":5,"spec_step":1,"spec_steps":[1,2,7]})");
    EXPECT_EQ(withoutTime(got[3]).find("spec_steps"), std::string::npos) << got[3];
    EXPECT_NE(withoutTime(got[3]).find(R"("spec_step":3})"), std::string::npos) << got[3];
}

TEST_F(SpecStreamTest, ATransitionCarriesItsStepOnlyWhenTheCaseNamedOne) {
    const std::string p = path("transition.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    s->transition(0, "notification", "phase1", "phase2", 4, {2});
    // Absent, not null, where the case said nothing: a reader of a case with no table
    // sees the line it always saw.
    s->transition(1, "deadline", "phase2", "inconclusive", -1);
    s->transition(2, "notification", "phase2", "pass", 5, {0});  // step 0 is a step

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 4u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"transition","step":0,"trigger":"notification","from":"phase1",)"
              R"("to":"phase2","pcap_frame_idx":4,"spec_step":2})");
    EXPECT_EQ(withoutTime(got[2]),
              R"({"event":"transition","step":1,"trigger":"deadline","from":"phase2",)"
              R"("to":"inconclusive","pcap_frame_idx":null})");
    EXPECT_NE(withoutTime(got[3]).find(R"("spec_step":0})"), std::string::npos) << got[3];
}

TEST_F(SpecStreamTest, ASendTakesTheInnermostStepAndTheOuterOneComesBack) {
    const std::string p = path("tx.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    ::tc8::stimulus::setTxObserver(s.get());

    ::tc8::stimulus::reportTx("udp_unicast", {}, 0, 0, 1);  // outside any step
    {
        ::tc8::stimulus::TxSpecStep one(1);
        ::tc8::stimulus::reportTx("udp_unicast", {}, 0, 0, 2);
        {
            ::tc8::stimulus::TxSpecStep two(2);
            ::tc8::stimulus::reportTx("udp_unicast", {}, 0, 0, 3);
        }
        ::tc8::stimulus::reportTx("udp_unicast", {}, 0, 0, 4);  // back in step 1
    }
    ::tc8::stimulus::reportTx("udp_unicast", {}, 0, 0, 5);  // and out again
    ::tc8::stimulus::setTxObserver(nullptr);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 6u);
    EXPECT_EQ(got[1].find("spec_step"), std::string::npos) << got[1];
    EXPECT_NE(got[2].find(R"("bytes":2,"spec_step":1)"), std::string::npos) << got[2];
    EXPECT_NE(got[3].find(R"("bytes":3,"spec_step":2)"), std::string::npos) << got[3];
    EXPECT_NE(got[4].find(R"("bytes":4,"spec_step":1)"), std::string::npos) << got[4];
    EXPECT_EQ(got[5].find("spec_step"), std::string::npos) << got[5];
}

TEST_F(SpecStreamTest, AStepOnOneThreadDoesNotTagAnotherThreadsSend) {
    const std::string p = path("threads.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    ::tc8::stimulus::setTxObserver(s.get());

    ::tc8::stimulus::TxSpecStep step(7);
    // A responder's own thread is not inside the case's step: its send is not the
    // case's step, whatever the case's thread is doing at that moment.
    std::thread other([] { ::tc8::stimulus::reportTx("tcp", {}, 0, 0, 9); });
    other.join();
    ::tc8::stimulus::setTxObserver(nullptr);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(got[1].find("spec_step"), std::string::npos) << got[1];
}

}  // namespace
