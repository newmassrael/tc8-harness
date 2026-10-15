// The live state-transition stream's file contract (sce_integration/state_stream.h):
// what a tailing reader may rely on. The runner wiring that feeds it is pinned
// through the production path in run_capture_test.cpp.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sce_integration/state_stream.h"

namespace {

namespace fs = std::filesystem;

// A scratch directory removed with the fixture; the stream is a regular file in it.
class StateStreamTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = fs::temp_directory_path() / ("state_stream_test_" + std::to_string(::getpid()));
        fs::create_directories(dir_);
    }
    void TearDown() override {
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

    fs::path dir_;
};

// Everything up to the sampled clock: the timestamp is a moving value, the rest is
// the contract.
std::string withoutTime(const std::string &line) {
    const auto at = line.rfind(",\"t_us\":");
    return at == std::string::npos ? line : line.substr(0, at) + "}";
}

TEST_F(StateStreamTest, WritesOneRecordPerLineInOrder) {
    const std::string p = path("a.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "hkmc:SOMEIPSRV_SD_BEHAVIOR_21");
    ASSERT_NE(s, nullptr);
    s->start("listening_phase1");
    s->transition(0, "someip_notification", "listening_phase1", "listening_phase2", 0);
    s->transition(1, "deadline_exceeded", "listening_phase2", "inconclusive", -1);
    s->end("inconclusive");

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 4u);
    EXPECT_EQ(withoutTime(got[0]),
              R"({"event":"start","case":"hkmc:SOMEIPSRV_SD_BEHAVIOR_21","initial":"listening_phase1"})");
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"transition","step":0,"trigger":"someip_notification",)"
              R"("from":"listening_phase1","to":"listening_phase2","pcap_frame_idx":0})");
    // No retained frame behind a timer firing: null, as trace.json has it.
    EXPECT_EQ(withoutTime(got[2]),
              R"({"event":"transition","step":1,"trigger":"deadline_exceeded",)"
              R"("from":"listening_phase2","to":"inconclusive","pcap_frame_idx":null})");
    EXPECT_EQ(withoutTime(got[3]), R"({"event":"end","final_state":"inconclusive"})");
    for (const auto &l : got) {
        EXPECT_NE(l.find(",\"t_us\":"), std::string::npos) << l;
    }
}

TEST_F(StateStreamTest, EscapesNamesLikeTheTrace) {
    const std::string p = path("b.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "c\"x");
    ASSERT_NE(s, nullptr);
    s->start("a\\b");
    const auto got = lines(p);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(withoutTime(got[0]), R"({"event":"start","case":"c\"x","initial":"a\\b"})");
}

TEST_F(StateStreamTest, EachRecordIsOnDiskBeforeTheNextIsWritten) {
    // The reader tails the file while the case runs: a record must be readable the
    // moment its call returns, not at close.
    const std::string p = path("c.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    s->start("s0");
    EXPECT_EQ(lines(p).size(), 1u);
    s->transition(0, "e", "s0", "s1", 3);
    EXPECT_EQ(lines(p).size(), 2u);
}

TEST_F(StateStreamTest, OpenTruncatesAPreviousRun) {
    const std::string p = path("d.ndjson");
    {
        auto s = ::tc8::sce::StateStream::open(p, "X");
        ASSERT_NE(s, nullptr);
        s->start("s0");
        s->end("s0");
    }
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    EXPECT_TRUE(lines(p).empty()) << "a re-run must not append to the previous run's record";
}

TEST_F(StateStreamTest, RefusesAPathItCannotWriteAsARegularFile) {
    EXPECT_EQ(::tc8::sce::StateStream::open(path("no_such_dir/e.ndjson"), "X"), nullptr);
    // A FIFO could block a write on its reader, or kill the process with SIGPIPE
    // once the reader leaves; neither may happen to the capture loop.
    const std::string fifo = path("f.fifo");
    ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0);
    EXPECT_EQ(::tc8::sce::StateStream::open(fifo, "X"), nullptr);
}

}  // namespace
