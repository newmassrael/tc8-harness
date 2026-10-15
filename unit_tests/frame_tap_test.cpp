// The state stream's passive frame observer: the header reader that reduces a captured
// frame to its addressing, and the tap that hands it frames from its own handle. The
// stream's `frame` line itself is pinned in state_stream_test.cpp.
//
// A live handle needs a privilege this suite does not have, so the tap is exercised over
// an offline source: the thread, the sink, the final drain and the stop are the same
// code a live handle runs, and what only a live run shows (the second handle's ring, the
// kernel's timestamps) is the on/off comparison's to cover.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <unistd.h>

#include "capture/frame_summary.h"
#include "capture/passive_tap.h"
#include "capture/pcap_source.h"
#include "sce_integration/state_stream.h"

namespace {

using Bytes = std::vector<std::uint8_t>;
using Proto = ::tc8::FrameSummary::Proto;

void put16(Bytes &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}

void putIp(Bytes &b, std::uint8_t a, std::uint8_t b1, std::uint8_t c, std::uint8_t d) {
    b.insert(b.end(), {a, b1, c, d});
}

// 14-byte Ethernet header with the given payload type, one optional VLAN tag first.
Bytes ethernet(std::uint16_t type, bool vlan = false) {
    Bytes b(6, 0xaa);
    b.insert(b.end(), 6, 0xbb);
    if (vlan) {
        put16(b, 0x8100);
        put16(b, 0x0005);  // priority/vlan id
    }
    put16(b, type);
    return b;
}

// An IPv4 header of `ihl_words` 32-bit words (5 = no options), then `l4` verbatim.
Bytes ipv4Frame(std::uint8_t proto, std::uint16_t frag_field, std::size_t ihl_words,
                const Bytes &l4, bool vlan = false) {
    Bytes b = ethernet(0x0800, vlan);
    b.push_back(static_cast<std::uint8_t>(0x40 | ihl_words));
    b.push_back(0);
    put16(b, static_cast<std::uint16_t>(ihl_words * 4 + l4.size()));
    put16(b, 0x1234);
    put16(b, frag_field);
    b.push_back(64);
    b.push_back(proto);
    put16(b, 0);
    putIp(b, 172, 16, 0, 1);
    putIp(b, 224, 244, 224, 245);
    b.insert(b.end(), (ihl_words - 5) * 4, 0);  // options
    b.insert(b.end(), l4.begin(), l4.end());
    return b;
}

Bytes ports(std::uint16_t src, std::uint16_t dst) {
    Bytes b;
    put16(b, src);
    put16(b, dst);
    b.insert(b.end(), 8, 0);
    return b;
}

::tc8::FrameSummary summarize(const Bytes &b) {
    return ::tc8::capture::summarizeEthernetFrame(b.data(), b.size(),
                                                  static_cast<std::uint32_t>(b.size()));
}

std::uint32_t ipBe(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    const std::uint8_t o[4] = {a, b, c, d};
    std::uint32_t v;
    std::memcpy(&v, o, sizeof(v));
    return v;
}

TEST(FrameSummaryTest, UdpCarriesAddressesAndPorts) {
    const auto s = summarize(ipv4Frame(17, 0, 5, ports(30490, 30491)));
    EXPECT_EQ(s.proto, Proto::kUdp);
    ASSERT_TRUE(s.has_ips);
    EXPECT_EQ(s.src_ip_be, ipBe(172, 16, 0, 1));
    EXPECT_EQ(s.dst_ip_be, ipBe(224, 244, 224, 245));
    ASSERT_TRUE(s.has_ports);
    EXPECT_EQ(s.src_port, 30490);
    EXPECT_EQ(s.dst_port, 30491);
}

TEST(FrameSummaryTest, TcpAndAVlanTagAreSteppedOver) {
    const auto s = summarize(ipv4Frame(6, 0, 5, ports(40000, 30509), /*vlan=*/true));
    EXPECT_EQ(s.proto, Proto::kTcp);
    ASSERT_TRUE(s.has_ports);
    EXPECT_EQ(s.src_port, 40000);
    EXPECT_EQ(s.dst_port, 30509);
}

TEST(FrameSummaryTest, IpOptionsMoveThePortsOffset) {
    const auto s = summarize(ipv4Frame(17, 0, 7, ports(1111, 2222)));
    ASSERT_TRUE(s.has_ports);
    EXPECT_EQ(s.src_port, 1111);
    EXPECT_EQ(s.dst_port, 2222);
}

TEST(FrameSummaryTest, ANonFirstFragmentHasNoPorts) {
    // Fragment offset 185: the bytes after the IP header are payload, not a UDP header.
    const auto s = summarize(ipv4Frame(17, 185, 5, ports(1, 2)));
    EXPECT_EQ(s.proto, Proto::kUdp);
    EXPECT_TRUE(s.has_ips);
    EXPECT_FALSE(s.has_ports);
}

TEST(FrameSummaryTest, AFrameCutShortYieldsWhatItsBytesHold) {
    Bytes cut = ipv4Frame(17, 0, 5, ports(30490, 30491));
    cut.resize(14 + 20 + 2);  // the snaplen ended inside the UDP header
    const auto s = ::tc8::capture::summarizeEthernetFrame(cut.data(), cut.size(), 60);
    EXPECT_TRUE(s.has_ips);
    EXPECT_FALSE(s.has_ports);
    EXPECT_EQ(s.wire_len, 60u) << "the wire length is the record's, not the captured part";

    // And one cut inside the IP header has no addresses to give.
    cut.resize(14 + 10);
    EXPECT_FALSE(::tc8::capture::summarizeEthernetFrame(cut.data(), cut.size(), 60).has_ips);
    // Nothing is read past the Ethernet header of a runt.
    EXPECT_FALSE(::tc8::capture::summarizeEthernetFrame(cut.data(), 5, 60).has_ips);
}

TEST(FrameSummaryTest, ArpCarriesSenderAndTargetAsOther) {
    Bytes b = ethernet(0x0806);
    put16(b, 1);       // hardware type: Ethernet
    put16(b, 0x0800);  // protocol type: IPv4
    b.push_back(6);
    b.push_back(4);
    put16(b, 2);  // reply
    b.insert(b.end(), 6, 0xcc);
    putIp(b, 172, 16, 0, 2);
    b.insert(b.end(), 6, 0xdd);
    putIp(b, 172, 16, 0, 1);
    const auto s = summarize(b);
    EXPECT_EQ(s.proto, Proto::kOther);
    ASSERT_TRUE(s.has_ips);
    EXPECT_EQ(s.src_ip_be, ipBe(172, 16, 0, 2));
    EXPECT_EQ(s.dst_ip_be, ipBe(172, 16, 0, 1));
    EXPECT_FALSE(s.has_ports);
}

TEST(FrameSummaryTest, OtherIpProtocolsAndNonIpFramesAreOther) {
    const auto icmp = summarize(ipv4Frame(1, 0, 5, Bytes(8, 0)));
    EXPECT_EQ(icmp.proto, Proto::kOther);
    EXPECT_TRUE(icmp.has_ips);
    EXPECT_FALSE(icmp.has_ports);

    Bytes v6 = ethernet(0x86dd);
    v6.insert(v6.end(), 40, 0);
    const auto s = summarize(v6);
    EXPECT_EQ(s.proto, Proto::kOther);
    EXPECT_FALSE(s.has_ips);
}

TEST(FrameSummaryTest, ARecordIsStampedInMicrosecondsWhateverTheHandlesPrecision) {
    const Bytes b = ipv4Frame(17, 0, 5, ports(1, 2));
    pcap_pkthdr hdr{};
    hdr.caplen = hdr.len = static_cast<bpf_u_int32>(b.size());
    hdr.ts.tv_sec = 1700000000;

    hdr.ts.tv_usec = 123456;  // a live handle: microseconds
    EXPECT_EQ(::tc8::capture::summarizePcapRecord(hdr, b.data(), /*nano=*/false).t_us,
              1700000000123456LL);
    hdr.ts.tv_usec = 123456789;  // an offline handle opened at nanosecond precision
    EXPECT_EQ(::tc8::capture::summarizePcapRecord(hdr, b.data(), /*nano=*/true).t_us,
              1700000000123456LL);
}

// The tap over the committed ARP fixture, writing into a real stream: every frame of
// the file becomes one frame line, in order, stamped with its own record's time, and
// the stream is left as it was found for the lines around them.
TEST(PassiveTapTest, EveryFrameOfTheSourceBecomesOneFrameLineInOrder) {
    namespace fs = std::filesystem;
    const fs::path fixture = fs::path(TC8_FIXTURE_DIR) / "decode_pcap_sample.pcap";

    // What the file holds, read independently of the tap.
    std::vector<std::int64_t> expect_t_us;
    {
        auto ref = ::tc8::capture::PcapSource::openOffline(fixture);
        ref->dispatch(-1, [&](const pcap_pkthdr &h, const u_char *d) {
            expect_t_us.push_back(::tc8::capture::summarizePcapRecord(h, d, true).t_us);
        });
    }
    ASSERT_FALSE(expect_t_us.empty());

    const fs::path out = fs::temp_directory_path() /
                         ("frame_tap_test_" + std::to_string(::getpid()) + ".ndjson");
    auto stream = ::tc8::sce::StateStream::open(out.string(), "X");
    ASSERT_NE(stream, nullptr);

    {
        auto src = ::tc8::capture::PcapSource::openOffline(fixture);
        ::tc8::capture::PassiveTap tap(std::move(src), [&](const pcap_pkthdr &h, const u_char *d) {
            stream->frame(::tc8::capture::summarizePcapRecord(h, d, true));
        });
        tap.start();
        // The thread delivers asynchronously; wait for the whole file, bounded.
        const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        std::size_t seen = 0;
        while (seen < expect_t_us.size() + 1 && std::chrono::steady_clock::now() < give_up) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            std::ifstream in(out);
            seen = 0;
            for (std::string l; std::getline(in, l);) ++seen;
        }
        tap.stop();
        tap.stop();  // idempotent
    }

    std::vector<std::string> lines;
    {
        std::ifstream in(out);
        for (std::string l; std::getline(in, l);) lines.push_back(l);
    }
    std::error_code ec;
    fs::remove(out, ec);

    ASSERT_EQ(lines.size(), expect_t_us.size() + 1) << "case_begin, then one line per frame";
    EXPECT_NE(lines[0].find(R"("event":"case_begin")"), std::string::npos);
    for (std::size_t i = 0; i < expect_t_us.size(); ++i) {
        const std::string &l = lines[i + 1];
        EXPECT_EQ(l.rfind(R"({"event":"frame")", 0), 0u) << l;
        // The line's t_us is the record's capture time, not the time it was written.
        EXPECT_NE(l.find(",\"t_us\":" + std::to_string(expect_t_us[i]) + "}"), std::string::npos)
            << l;
    }
}

TEST(PassiveTapTest, TheSinkIsNeverCalledAfterStop) {
    namespace fs = std::filesystem;
    auto src = ::tc8::capture::PcapSource::openOffline(fs::path(TC8_FIXTURE_DIR) /
                                                       "decode_pcap_sample.pcap");
    std::size_t calls = 0;
    ::tc8::capture::PassiveTap tap(std::move(src),
                                   [&](const pcap_pkthdr &, const u_char *) { ++calls; });
    tap.start();
    tap.stop();
    const std::size_t at_stop = calls;
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    EXPECT_EQ(calls, at_stop);
}

}  // namespace
