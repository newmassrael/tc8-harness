// The live state-transition stream's file contract (sce_integration/state_stream.h):
// what a tailing reader may rely on. The runner wiring that feeds it is pinned
// through the production path in run_capture_test.cpp.

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sce_integration/state_stream.h"
#include "stimulus/tx_observer.h"

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
    ASSERT_EQ(got.size(), 5u);
    EXPECT_EQ(withoutTime(got[0]),
              R"({"event":"case_begin","case":"hkmc:SOMEIPSRV_SD_BEHAVIOR_21"})");
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"start","case":"hkmc:SOMEIPSRV_SD_BEHAVIOR_21","initial":"listening_phase1"})");
    EXPECT_EQ(withoutTime(got[2]),
              R"({"event":"transition","step":0,"trigger":"someip_notification",)"
              R"("from":"listening_phase1","to":"listening_phase2","pcap_frame_idx":0})");
    // No retained frame behind a timer firing: null, as trace.json has it.
    EXPECT_EQ(withoutTime(got[3]),
              R"({"event":"transition","step":1,"trigger":"deadline_exceeded",)"
              R"("from":"listening_phase2","to":"inconclusive","pcap_frame_idx":null})");
    EXPECT_EQ(withoutTime(got[4]), R"({"event":"end","final_state":"inconclusive"})");
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
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(withoutTime(got[0]), R"({"event":"case_begin","case":"c\"x"})");
    EXPECT_EQ(withoutTime(got[1]), R"({"event":"start","case":"c\"x","initial":"a\\b"})");
}

TEST_F(StateStreamTest, EachRecordIsOnDiskBeforeTheNextIsWritten) {
    // The reader tails the file while the case runs: a record must be readable the
    // moment its call returns, not at close.
    const std::string p = path("c.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(lines(p).size(), 1u);  // case_begin, already readable
    s->start("s0");
    EXPECT_EQ(lines(p).size(), 2u);
    s->transition(0, "e", "s0", "s1", 3);
    EXPECT_EQ(lines(p).size(), 3u);
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
    // Only the new run's own case_begin: nothing of the previous run's start/end.
    const auto got = lines(p);
    ASSERT_EQ(got.size(), 1u) << "a re-run must not append to the previous run's record";
    EXPECT_EQ(withoutTime(got[0]), R"({"event":"case_begin","case":"X"})");
}

TEST_F(StateStreamTest, TxLineNamesTheEmitterTheTransportAndWhereItWent) {
    const std::string p = path("tx.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);

    ::tc8::stimulus::TxEvent ev;
    ev.emitter = "emitFindServiceBoot";
    ev.transport = "udp_multicast";
    ev.iface = "veth-tester";
    // 224.244.224.245 in network byte order: the first octet is the lowest byte.
    const unsigned char group[4] = {224, 244, 224, 245};
    std::memcpy(&ev.dst_ip_be, group, sizeof(group));
    ev.dst_port = 30490;
    ev.bytes = 56;
    s->onTx(ev);

    // A raw frame is opaque to its sender: no destination, no emitter when no entry
    // point named it, and no interface when the primitive takes none.
    ::tc8::stimulus::TxEvent raw;
    raw.transport = "ethernet";
    raw.bytes = 42;
    s->onTx(raw);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 3u);  // case_begin, then the two tx lines
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"tx","emitter":"emitFindServiceBoot","transport":"udp_multicast",)"
              R"("iface":"veth-tester","dst":"224.244.224.245:30490","bytes":56})");
    // No entry point named it: kept, with a null name, so the gap is visible.
    EXPECT_EQ(withoutTime(got[2]),
              R"({"event":"tx","emitter":null,"transport":"ethernet","bytes":42})");
}

TEST_F(StateStreamTest, StimulusIsBracketedAndTxLinesAreBounded) {
    const std::string p = path("bound.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    s->stimulusBegin();
    ::tc8::stimulus::TxEvent ev;
    ev.emitter = "emitBurst";
    ev.transport = "udp_unicast";
    for (int i = 0; i < 1500; ++i) s->onTx(ev);
    s->stimulusEnd();

    const auto got = lines(p);
    // case_begin + stimulus_begin + 1000 tx + tx_suppressed + stimulus_end
    ASSERT_EQ(got.size(), 1004u);
    EXPECT_EQ(withoutTime(got[1]), R"({"event":"stimulus_begin"})");
    EXPECT_EQ(withoutTime(got[1001]),
              R"({"event":"tx","emitter":"emitBurst","transport":"udp_unicast","bytes":0})");
    EXPECT_EQ(withoutTime(got[1002]), R"({"event":"tx_suppressed","after":1000})");
    EXPECT_EQ(withoutTime(got[1003]), R"({"event":"stimulus_end"})");
}

TEST_F(StateStreamTest, FrameLineCarriesTheCaptureTimeAndWhatTheHeadersHold) {
    const std::string p = path("frame.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);

    ::tc8::FrameSummary udp;
    udp.t_us = 1700000000123456LL;
    udp.wire_len = 98;
    udp.proto = ::tc8::FrameSummary::Proto::kUdp;
    udp.has_ips = true;
    const unsigned char src[4] = {172, 16, 0, 2};
    const unsigned char dst[4] = {224, 244, 224, 245};
    std::memcpy(&udp.src_ip_be, src, sizeof(src));
    std::memcpy(&udp.dst_ip_be, dst, sizeof(dst));
    udp.has_ports = true;
    udp.src_port = 30490;
    udp.dst_port = 30490;
    s->frame(udp);

    // A frame the readers cannot address: kept, with only what is known.
    ::tc8::FrameSummary raw;
    raw.t_us = 1700000000123999LL;
    raw.wire_len = 60;
    s->frame(raw);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 3u);
    // The line's t_us is the frame's capture time, not the time of writing.
    EXPECT_EQ(got[1],
              R"({"event":"frame","src_ip":"172.16.0.2","dst_ip":"224.244.224.245",)"
              R"("proto":"udp","src_port":30490,"dst_port":30490,"len":98,)"
              R"("t_us":1700000000123456})");
    EXPECT_EQ(got[2],
              R"({"event":"frame","proto":"other","len":60,"t_us":1700000000123999})");
}

TEST_F(StateStreamTest, FrameLinesAreBoundedAndTheObserverSaysOnceThatItIsGone) {
    const std::string p = path("frame_bound.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);

    s->observerUnavailable("pcap_activate failed: \"Operation not permitted\"");
    s->observerUnavailable("again");  // at most one line

    ::tc8::FrameSummary f;
    f.t_us = 1;
    for (int i = 0; i < 6000; ++i) s->frame(f);

    const auto got = lines(p);
    // case_begin + observer_unavailable + 5000 frame + frame_suppressed
    ASSERT_EQ(got.size(), 5003u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"observer_unavailable","reason":)"
              R"("pcap_activate failed: \"Operation not permitted\""})");
    EXPECT_EQ(withoutTime(got[5001]), R"({"event":"frame","proto":"other","len":0})");
    EXPECT_EQ(withoutTime(got[5002]), R"({"event":"frame_suppressed","after":5000})");
}

TEST(TxObserver, TheOutermostScopeNamesTheSendAndNoObserverMeansNoReport) {
    struct Capture final : ::tc8::stimulus::ITxObserver {
        std::vector<std::string> emitters;
        void onTx(const ::tc8::stimulus::TxEvent &ev) override {
            emitters.emplace_back(ev.emitter);
        }
    } capture;

    // No observer: a send reports nothing and costs nothing.
    ::tc8::stimulus::reportTx("udp_unicast", "", 0, 0, 1);

    ::tc8::stimulus::setTxObserver(&capture);
    {
        // A case calls the outer emitter, which calls another underneath it.
        ::tc8::stimulus::TxScope outer("emitOuter");
        {
            ::tc8::stimulus::TxScope inner("emitInner");
            ::tc8::stimulus::reportTx("udp_unicast", "", 0, 0, 1);
        }
        // Leaving the inner scope must not drop the outer name.
        ::tc8::stimulus::reportTx("udp_unicast", "", 0, 0, 1);
    }
    // Outside every scope the send names no emitter.
    ::tc8::stimulus::reportTx("udp_unicast", "", 0, 0, 1);
    ::tc8::stimulus::setTxObserver(nullptr);
    ::tc8::stimulus::reportTx("udp_unicast", "", 0, 0, 1);

    ASSERT_EQ(capture.emitters.size(), 3u);
    EXPECT_EQ(capture.emitters[0], "emitOuter");
    EXPECT_EQ(capture.emitters[1], "emitOuter");
    EXPECT_EQ(capture.emitters[2], "");
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
