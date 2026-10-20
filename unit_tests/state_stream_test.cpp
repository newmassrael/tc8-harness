// The live state-transition stream's file contract (sce_integration/state_stream.h):
// what a tailing reader may rely on. The runner wiring that feeds it is pinned
// through the production path in run_capture_test.cpp.

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sce_integration/state_stream.h"
#include "stimulus/endpoint.h"
#include "stimulus/subscribe_tcp_session.h"
#include "stimulus/tcp_client.h"
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
    auto s = ::tc8::sce::StateStream::open(p, "ext:SOMEIPSRV_SD_BEHAVIOR_21");
    ASSERT_NE(s, nullptr);
    s->start("listening_phase1");
    s->transition(0, "someip_notification", "listening_phase1", "listening_phase2", 0);
    s->transition(1, "deadline_exceeded", "listening_phase2", "inconclusive", -1);
    s->end("inconclusive");

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 5u);
    EXPECT_EQ(withoutTime(got[0]),
              R"({"event":"case_begin","case":"ext:SOMEIPSRV_SD_BEHAVIOR_21"})");
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"start","case":"ext:SOMEIPSRV_SD_BEHAVIOR_21","initial":"listening_phase1"})");
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

TEST_F(StateStreamTest, ATxLineOnATcpConnectionCarriesTheTestersPort) {
    const std::string p = path("tcp.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);

    ::tc8::stimulus::TxEvent ev;
    ev.transport = "tcp_connect_ack";
    const unsigned char dut[4] = {10, 0, 0, 2};
    std::memcpy(&ev.dst_ip_be, dut, sizeof(dut));
    ev.dst_port = 30509;
    ev.src_port = 40001;
    s->onTx(ev);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"tx","emitter":null,"transport":"tcp_connect_ack",)"
              R"("dst":"10.0.0.2:30509","src_port":40001,"bytes":0})");
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

TEST_F(StateStreamTest, MachineLineDeclaresStatesAndEventsAndSaysTransitionsAreUnknown) {
    const std::string p = path("machine.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);

    ::tc8::sce::MachineDescription d;
    d.states = {{"listening", true, false}, {"pass", false, true}, {"fa\"il", false, true}};
    d.events = {"arp_observed", "error.execution"};
    s->machine(d);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"machine","states":[{"id":"listening","initial":true,"final":false},)"
              R"({"id":"pass","initial":false,"final":true},)"
              R"({"id":"fa\"il","initial":false,"final":true}],)"
              R"("events":["arp_observed","error.execution"],"transitions":null})");
}

TEST_F(StateStreamTest, MachineLineCarriesItsTransitionsAndNullForWhatItHasNoIdFor) {
    const std::string p = path("machine_transitions.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);

    ::tc8::sce::MachineDescription d;
    d.states = {{"listening", true, false}, {"pass", false, true}};
    d.events = {"arp_observed"};
    // The second has no event id (eventless or a wildcard), the third no target.
    d.transitions = std::vector<::tc8::sce::MachineDescription::Transition>{
        {"listening", "pass", "arp_observed", 0},
        {"listening", "pass", std::nullopt, 1},
        {"listening", std::nullopt, "arp_observed", 2}};
    d.source_hash = "ab12";
    s->machine(d);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"machine","states":[{"id":"listening","initial":true,"final":false},)"
              R"({"id":"pass","initial":false,"final":true}],"events":["arp_observed"],)"
              R"("transitions":[{"from":"listening","to":"pass","event":"arp_observed","index":0},)"
              R"({"from":"listening","to":"pass","event":null,"index":1},)"
              R"({"from":"listening","to":null,"event":"arp_observed","index":2}],)"
              R"("source_hash":"ab12"})");
}

TEST_F(StateStreamTest, TheSourceHashRidesWithTheListAndNeverWithoutIt) {
    const std::string p = path("machine_source_hash.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);

    ::tc8::sce::MachineDescription d;
    d.states = {{"only", true, true}};
    // A hash with no table says nothing about a table, so it is not written.
    d.source_hash = "ab12";
    s->machine(d);
    d.transitions = std::vector<::tc8::sce::MachineDescription::Transition>{};
    s->machine(d);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(got[1].find("source_hash"), std::string::npos) << got[1];
    EXPECT_NE(got[2].find(R"("transitions":[],"source_hash":"ab12")"), std::string::npos) << got[2];
}

TEST_F(StateStreamTest, AnEmptyTableIsAListAndNoTableIsNull) {
    const std::string p = path("machine_empty_table.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);

    ::tc8::sce::MachineDescription d;
    d.states = {{"only", true, true}};
    d.transitions = std::vector<::tc8::sce::MachineDescription::Transition>{};
    s->machine(d);
    d.transitions.reset();
    s->machine(d);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 3u);
    // A machine that declares its table and has no transitions: "these are all of them".
    EXPECT_NE(got[1].find(R"("transitions":[])"), std::string::npos) << got[1];
    EXPECT_NE(got[2].find(R"("transitions":null)"), std::string::npos) << got[2];
}

TEST_F(StateStreamTest, ATableAgainstItsOwnNamesIsValidatedAndTheProblemsAreStreamed) {
    ::tc8::sce::MachineDescription d;
    d.states = {{"a", true, false}, {"b", false, true}};
    d.events = {"go"};

    // No table is not a problem: nothing was claimed.
    EXPECT_TRUE(::tc8::sce::validateTransitions(d).empty());

    d.transitions = std::vector<::tc8::sce::MachineDescription::Transition>{
        {"a", "b", "go", 0}, {"a", std::nullopt, std::nullopt, 1}, {"b", std::nullopt, std::nullopt, 0}};
    EXPECT_TRUE(::tc8::sce::validateTransitions(d).empty());

    d.transitions = std::vector<::tc8::sce::MachineDescription::Transition>{
        {"ghost", "b", "go", 0},     // departs from an unknown state
        {"a", "nowhere", "go", 0},   // arrives at one
        {"a", "b", "stop", 1},       // is triggered by an unnamed event
        {"a", "b", "go", 1}};        // repeats an index of its state
    const auto problems = ::tc8::sce::validateTransitions(d);
    ASSERT_EQ(problems.size(), 4u);
    EXPECT_NE(problems[0].find("ghost"), std::string::npos) << problems[0];
    EXPECT_NE(problems[1].find("nowhere"), std::string::npos) << problems[1];
    EXPECT_NE(problems[2].find("stop"), std::string::npos) << problems[2];
    EXPECT_NE(problems[3].find("repeats the index"), std::string::npos) << problems[3];

    const std::string p = path("transitions_invalid.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    s->transitionsInvalid({"a \"quoted\" problem"});
    const auto got = lines(p);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"transitions_invalid","problems":["a \"quoted\" problem"]})");
}

TEST_F(StateStreamTest, NothingIsWrittenAfterEnd) {
    // A thread the case detached, or the frame observer, may offer a line after the
    // run has ended; `end` has to stay the last line.
    const std::string p = path("after_end.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    s->start("s0");
    s->end("s0");

    ::tc8::stimulus::TxEvent ev;
    ev.transport = "udp_unicast";
    s->onTx(ev);
    ::tc8::FrameSummary f;
    s->frame(f);
    s->end("again");

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 3u);  // case_begin, start, end
    EXPECT_EQ(withoutTime(got[2]), R"({"event":"end","final_state":"s0"})");
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

TEST(TxObserver, ClearingWaitsForASenderStillInsideAReport) {
    // A sender on a thread of its own may be inside a report when the case ends and the
    // observer is about to be destroyed: clearing must not return until it has left.
    struct Slow final : ::tc8::stimulus::ITxObserver {
        std::atomic<bool> entered{false};
        std::atomic<bool> left{false};
        void onTx(const ::tc8::stimulus::TxEvent &) override {
            entered = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            left = true;
        }
    } slow;

    ::tc8::stimulus::setTxObserver(&slow);
    std::thread sender([] { ::tc8::stimulus::reportTx("udp_unicast", "", 0, 0, 1); });
    while (!slow.entered) std::this_thread::yield();
    ::tc8::stimulus::setTxObserver(nullptr);
    EXPECT_TRUE(slow.left) << "cleared while a report was still running";
    sender.join();
}

TEST(TxObserver, AConnectedSocketIsReportedWithItsPeer) {
    struct Capture final : ::tc8::stimulus::ITxObserver {
        std::uint32_t ip = 0;
        std::uint16_t port = 0;
        std::uint16_t src_port = 0;
        std::size_t bytes = 0;
        std::string transport;
        void onTx(const ::tc8::stimulus::TxEvent &ev) override {
            ip = ev.dst_ip_be;
            port = ev.dst_port;
            src_port = ev.src_port;
            bytes = ev.bytes;
            transport = ev.transport;
        }
    } capture;

    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr *>(&a), sizeof(a)), 0);
    ASSERT_EQ(::listen(listener, 1), 0);
    socklen_t len = sizeof(a);
    ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr *>(&a), &len), 0);
    const int client = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_EQ(::connect(client, reinterpret_cast<sockaddr *>(&a), sizeof(a)), 0);

    sockaddr_in local{};
    len = sizeof(local);
    ASSERT_EQ(::getsockname(client, reinterpret_cast<sockaddr *>(&local), &len), 0);

    ::tc8::stimulus::setTxObserver(&capture);
    ::tc8::stimulus::reportTxConnected("tcp", client, 4);
    ::tc8::stimulus::setTxObserver(nullptr);
    ::close(client);
    ::close(listener);

    EXPECT_EQ(capture.transport, "tcp");
    EXPECT_EQ(capture.ip, htonl(INADDR_LOOPBACK));
    EXPECT_EQ(capture.port, ntohs(a.sin_port));
    // The tester's own end: with the peer it names which connection carried the send.
    EXPECT_EQ(capture.src_port, ntohs(local.sin_port));
    EXPECT_EQ(capture.bytes, 4u);
}

// What a handshake the tester opens reports, through the production connect: the SYN
// and the completing ACK, each with the step a TxConnectSteps names, both on the
// connection the connect made.
TEST(TxObserver, AConnectReportsTheSynAndTheAckWithTheirOwnSteps) {
    struct Capture final : ::tc8::stimulus::ITxObserver {
        struct Seen {
            std::string   transport;
            int           step;
            std::uint16_t dst_port;
            std::uint16_t src_port;
        };
        std::vector<Seen> seen;
        void onTx(const ::tc8::stimulus::TxEvent &ev) override {
            seen.push_back({ev.transport, ev.spec_step, ev.dst_port, ev.src_port});
        }
    } capture;

    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr *>(&a), sizeof(a)), 0);
    ASSERT_EQ(::listen(listener, 8), 0);
    socklen_t len = sizeof(a);
    ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr *>(&a), &len), 0);
    const ::tc8::stimulus::Endpoint dut{htonl(INADDR_LOOPBACK), ntohs(a.sin_port)};

    // Opens one connection and returns the tester's port, so each pair of reports can be
    // held to the connection that made it.
    const auto connectOnce = [&]() -> std::uint16_t {
        std::uint16_t local_port = 0;
        const int fd = ::tc8::stimulus::connectTcpFromIface("lo", dut, 0, &local_port);
        EXPECT_GE(fd, 0);
        if (fd >= 0) ::close(fd);
        return local_port;
    };

    ::tc8::stimulus::setTxObserver(&capture);
    std::uint16_t named = 0;
    std::uint16_t inner = 0;
    std::uint16_t restored = 0;
    std::uint16_t unnamed = 0;
    {
        ::tc8::stimulus::TxSpecStep request(40);
        {
            ::tc8::stimulus::TxConnectSteps handshake(41, 42);
            named = connectOnce();
            {
                // A step of its own for the SYN only: the ACK is left untagged rather
                // than taking the request's step.
                ::tc8::stimulus::TxConnectSteps syn_only(43, ::tc8::stimulus::kNoSpecStep);
                inner = connectOnce();
            }
            restored = connectOnce();
        }
        // Without one, both segments take the step the send is in, as any send does.
        unnamed = connectOnce();
    }
    ::tc8::stimulus::setTxObserver(nullptr);
    ::close(listener);

    using Seen = Capture::Seen;
    const std::uint16_t port = dut.port;
    const std::vector<Seen> want = {
        {"tcp_connect", 41, port, named},     {"tcp_connect_ack", 42, port, named},
        {"tcp_connect", 43, port, inner},     {"tcp_connect_ack", -1, port, inner},
        {"tcp_connect", 41, port, restored},  {"tcp_connect_ack", 42, port, restored},
        {"tcp_connect", 40, port, unnamed},   {"tcp_connect_ack", 40, port, unnamed},
    };
    ASSERT_EQ(capture.seen.size(), want.size());
    for (std::size_t i = 0; i < want.size(); ++i) {
        EXPECT_EQ(capture.seen[i].transport, want[i].transport) << i;
        EXPECT_EQ(capture.seen[i].step, want[i].step) << i;
        EXPECT_EQ(capture.seen[i].dst_port, want[i].dst_port) << i;
        EXPECT_EQ(capture.seen[i].src_port, want[i].src_port) << i;
        EXPECT_NE(capture.seen[i].src_port, 0u) << i;
    }
}

// The tester's abortive close is the one place it puts an RST on the wire itself, and it
// reports it with both ends of the connection it reset, from what the session holds.
TEST(TxObserver, AnAbortiveCloseReportsTheResetWithBothEndsAndTheStep) {
    struct Capture final : ::tc8::stimulus::ITxObserver {
        std::vector<::tc8::stimulus::TxEvent> seen;
        std::vector<std::string>              transports;
        void onTx(const ::tc8::stimulus::TxEvent &ev) override {
            seen.push_back(ev);
            transports.emplace_back(ev.transport);
        }
    } capture;

    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr *>(&a), sizeof(a)), 0);
    ASSERT_EQ(::listen(listener, 8), 0);
    socklen_t len = sizeof(a);
    ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr *>(&a), &len), 0);
    const ::tc8::stimulus::Endpoint dut{htonl(INADDR_LOOPBACK), ntohs(a.sin_port)};

    ::tc8::stimulus::SubscribeEventgroupTcpSession session("lo", dut);
    ASSERT_TRUE(session.valid());
    const std::uint16_t local_port = session.localPort();

    ::tc8::stimulus::setTxObserver(&capture);
    {
        ::tc8::stimulus::TxSpecStep step(44);
        session.refuseWithRst();
        session.refuseWithRst();  // already closed: nothing more is reset, or reported
    }
    ::tc8::stimulus::setTxObserver(nullptr);
    ::close(listener);

    ASSERT_EQ(capture.seen.size(), 1u);
    EXPECT_EQ(capture.transports[0], "tcp_reset");
    EXPECT_EQ(capture.seen[0].spec_step, 44);
    EXPECT_EQ(capture.seen[0].dst_ip_be, htonl(INADDR_LOOPBACK));
    EXPECT_EQ(capture.seen[0].dst_port, dut.port);
    EXPECT_EQ(capture.seen[0].src_port, local_port);
    EXPECT_NE(local_port, 0u);
}

// A port the tester leaves unserved has no call to hook, so the case declares it; the
// line names the port refused and no destination, since the SYN has not arrived.
TEST_F(StateStreamTest, ARefusedPortIsALineWithItsPortAndNoDestination) {
    const std::string p = path("refuse.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    ::tc8::stimulus::setTxObserver(s.get());
    {
        ::tc8::stimulus::TxSpecStep step(45);
        ::tc8::stimulus::reportTcpRefusal("veth-tester", 30509);
    }
    ::tc8::stimulus::setTxObserver(nullptr);

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"tx","emitter":null,"transport":"tcp_refuse","iface":"veth-tester",)"
              R"("src_port":30509,"bytes":0,"spec_step":45})");
}

// An action that puts nothing on the wire still carries the emitter scope and the step,
// and names what it was; the label is the case's word, so it is escaped and never read.
TEST_F(StateStreamTest, ATesterActionIsALineWithItsLabelAndNothingOnTheWire) {
    const std::string p = path("action.ndjson");
    auto s = ::tc8::sce::StateStream::open(p, "X");
    ASSERT_NE(s, nullptr);
    ::tc8::stimulus::setTxObserver(s.get());
    {
        ::tc8::stimulus::TxScope scope("holdFor");
        ::tc8::stimulus::TxSpecStep step(46);
        ::tc8::stimulus::reportTesterAction("wait");
    }
    ::tc8::stimulus::reportTesterAction("a\"b");  // outside any scope or step
    ::tc8::stimulus::setTxObserver(nullptr);
    ::tc8::stimulus::reportTesterAction("after");  // no observer: nothing

    const auto got = lines(p);
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(withoutTime(got[1]),
              R"({"event":"tx","emitter":"holdFor","transport":"tester_action",)"
              R"("action":"wait","bytes":0,"spec_step":46})");
    EXPECT_EQ(withoutTime(got[2]),
              R"({"event":"tx","emitter":null,"transport":"tester_action",)"
              R"("action":"a\"b","bytes":0})");
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
