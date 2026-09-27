// Regression guard for the reliable-transport frame-timestamp fix: a SOME/IP
// message reassembled out of a TCP stream must carry the packet's arrival
// timestamp on `SomeIpFrame::observed_ts_us`. The UDP path stamps it inline; the
// TCP stream-follower callbacks (onClientData / onServerData) must stamp it from
// the packet currently in follower_.process_packet. Without the fix these frames
// read observed_ts_us == 0, so frame_delta_us() is structurally 0 for consecutive
// TCP SOME/IP frames and every reliable-transport inter-frame timing guard fails.
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include <gtest/gtest.h>
#include <pcap/pcap.h>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/rawpdu.h>
#include <tins/tcp.h>
#include <tins/udp.h>

#include "dissect/packet_pipeline.h"
#include "tc8/captured_event.h"
#include "tc8/stimulus_marker.h"

namespace {

const std::string kTesterMac = "02:00:00:00:00:01";
const std::string kDutMac = "02:00:00:00:00:02";
const std::string kTesterIp = "192.168.0.10";
const std::string kDutIp = "192.168.0.1";

// 16-byte SOME/IP magic cookie header: svc 0xFFFF, mth 0x8000, length 8,
// client 0xDEAD, session 0xBEEF, proto 1, iface 1, msgtype 1, retcode 0.
std::vector<std::uint8_t> cookie() {
    return {0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x08,
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x01, 0x01, 0x00};
}

std::vector<std::uint8_t> tcpEth(const std::string &dmac, const std::string &smac,
                                 const std::string &sip, const std::string &dip,
                                 std::uint16_t sport, std::uint16_t dport, std::uint32_t seq,
                                 std::uint32_t ack, bool syn, bool ack_flag, bool psh,
                                 const std::vector<std::uint8_t> &payload = {}) {
    Tins::TCP tcp(dport, sport);
    tcp.seq(seq);
    tcp.ack_seq(ack);
    tcp.set_flag(Tins::TCP::SYN, syn ? 1 : 0);
    tcp.set_flag(Tins::TCP::ACK, ack_flag ? 1 : 0);
    tcp.set_flag(Tins::TCP::PSH, psh ? 1 : 0);
    if (!payload.empty()) {
        tcp.inner_pdu(Tins::RawPDU(payload.data(), payload.size()));
    }
    Tins::IP ip(dip, sip);
    ip.inner_pdu(tcp);
    Tins::EthernetII eth(dmac, smac);
    eth.inner_pdu(ip);
    const auto ser = eth.serialize();
    return std::vector<std::uint8_t>(ser.begin(), ser.end());
}

std::vector<std::uint8_t> udpEth(const std::string &dmac, const std::string &smac,
                                 const std::string &sip, const std::string &dip,
                                 std::uint16_t sport, std::uint16_t dport,
                                 const std::vector<std::uint8_t> &payload) {
    Tins::UDP udp(dport, sport);
    udp.inner_pdu(Tins::RawPDU(payload.data(), payload.size()));
    Tins::IP ip(dip, sip);
    ip.inner_pdu(udp);
    Tins::EthernetII eth(dmac, smac);
    eth.inner_pdu(ip);
    const auto ser = eth.serialize();
    return std::vector<std::uint8_t>(ser.begin(), ser.end());
}

pcap_pkthdr hdrAt(long long ts_us, std::size_t len) {
    pcap_pkthdr h{};
    h.ts.tv_sec = static_cast<decltype(h.ts.tv_sec)>(ts_us / 1'000'000);
    h.ts.tv_usec = static_cast<decltype(h.ts.tv_usec)>(ts_us % 1'000'000);
    h.caplen = static_cast<std::uint32_t>(len);
    h.len = static_cast<std::uint32_t>(len);
    return h;
}

void feed(tc8::dissect::PacketPipeline &pipe, long long ts_us, const std::vector<std::uint8_t> &f) {
    const auto h = hdrAt(ts_us, f.size());
    pipe.processFrame(h, f.data(), DLT_EN10MB);
}

}  // namespace

// A cookie in EACH direction over one followed stream exercises both stamping
// paths (client -> onClientData, server -> onServerData). Each reassembled
// SOME/IP frame must carry its own packet's arrival timestamp.
TEST(PacketPipelineTcpTimestamp, ReassembledSomeIpFramesCarryArrivalTs) {
    std::vector<tc8::SomeIpFrame> frames;
    tc8::dissect::PacketPipeline pipe([&](const tc8::CapturedEvent &ev) {
        if (const auto *f = std::get_if<tc8::SomeIpFrame>(&ev)) {
            frames.push_back(*f);
        }
    });

    // Handshake (SYN / SYN-ACK) then a cookie each way. These seqs are the same
    // ones the decode-pcap golden fixture uses, so libtins follows the stream.
    feed(pipe, 1000, tcpEth(kDutMac, kTesterMac, kTesterIp, kDutIp, 50001, 30501, 2000, 0,
                            /*syn=*/true, /*ack=*/false, /*psh=*/false));
    feed(pipe, 2000, tcpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, 30501, 50001, 6000, 2001,
                            /*syn=*/true, /*ack=*/true, /*psh=*/false));
    feed(pipe, 16000, tcpEth(kDutMac, kTesterMac, kTesterIp, kDutIp, 50001, 30501, 2001, 6001,
                             /*syn=*/false, /*ack=*/true, /*psh=*/true, cookie()));
    feed(pipe, 17000, tcpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, 30501, 50001, 6001, 2017,
                             /*syn=*/false, /*ack=*/true, /*psh=*/true, cookie()));

    ASSERT_EQ(frames.size(), 2u);
    for (const auto &f : frames) {
        EXPECT_TRUE(f.is_tcp);
        EXPECT_EQ(f.service_id, 0xFFFFu);
        EXPECT_EQ(f.method_id, 0x8000u);
    }
    // The client cookie (idx 16000) and the server cookie (idx 17000) each carry
    // their own arrival stamp — the fix. Before it, both were 0.
    EXPECT_EQ(frames[0].observed_ts_us, 16000);
    EXPECT_EQ(frames[1].observed_ts_us, 17000);
    EXPECT_GT(frames[1].observed_ts_us - frames[0].observed_ts_us, 0);
}

// Regression guard for the control-plane grading defect. A case whose SCXML
// grades the first datagram in its listen window (`dispatchUdpFrame` raises
// Udp_observed for EVERY UdpFrame) graded the DUT-control channel's response
// instead of the datagram the case exists to observe, which arrived microseconds
// later and was never considered. The first block pins the premise so this test
// fails if the ordering hazard ever stops being real; the second pins the fix.
TEST(PacketPipelineControlPlane, ControlResponseWithheldSoTheDataDatagramIsSeenFirst) {
    constexpr std::uint16_t kControlPort = 30600;
    constexpr std::uint16_t kCaseSrcPort = 20001;

    const auto control =
        udpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, kControlPort, 45000, {0x01});
    const auto data =
        udpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, kCaseSrcPort, 20000, {0x02});

    {
        std::vector<tc8::UdpFrame> seen;
        tc8::dissect::PacketPipeline pipe([&](const tc8::CapturedEvent &ev) {
            if (const auto *f = std::get_if<tc8::UdpFrame>(&ev)) {
                seen.push_back(*f);
            }
        });
        feed(pipe, 1000, control);
        feed(pipe, 1072, data);
        ASSERT_EQ(seen.size(), 2u);
        EXPECT_EQ(seen[0].src_port, kControlPort);
        EXPECT_EQ(pipe.controlPlaneFrames(), 0u);
    }

    std::vector<tc8::UdpFrame> seen;
    tc8::dissect::PacketPipeline pipe([&](const tc8::CapturedEvent &ev) {
        if (const auto *f = std::get_if<tc8::UdpFrame>(&ev)) {
            seen.push_back(*f);
        }
    });
    pipe.setControlPlanePort(kControlPort);
    feed(pipe, 1000, control);
    feed(pipe, 1072, data);

    ASSERT_EQ(seen.size(), 1u);
    EXPECT_EQ(seen[0].src_port, kCaseSrcPort);
    EXPECT_EQ(pipe.controlPlaneFrames(), 1u);
}

// Both halves of an exchange are control plane (request TO the port, response
// FROM it), and the decision is taken per PACKET: the Ipv4Frame every IPv4
// packet also emits carries no transport ports, so it could not be classified
// downstream at all and has to be withheld together with the UdpFrame.
TEST(PacketPipelineControlPlane, BothDirectionsAndEveryAlternativeOfThePacket) {
    constexpr std::uint16_t kControlPort = 30700;
    std::size_t udp_events = 0;
    std::size_t ipv4_events = 0;
    tc8::dissect::PacketPipeline pipe([&](const tc8::CapturedEvent &ev) {
        if (std::holds_alternative<tc8::UdpFrame>(ev)) {
            ++udp_events;
        }
        if (std::holds_alternative<tc8::Ipv4Frame>(ev)) {
            ++ipv4_events;
        }
    });
    pipe.setControlPlanePort(kControlPort);
    feed(pipe, 1000, udpEth(kDutMac, kTesterMac, kTesterIp, kDutIp, 45000, kControlPort, {0x01}));
    feed(pipe, 2000, udpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, kControlPort, 45000, {0x02}));

    EXPECT_EQ(udp_events, 0u);
    EXPECT_EQ(ipv4_events, 0u);
    EXPECT_EQ(pipe.controlPlaneFrames(), 2u);
}

// The seam's two backends are free to differ on transport
// (`TestabilityConfig::use_tcp`), so a TCP control channel is excluded on the
// same rule — and traffic on any other port is left entirely alone.
TEST(PacketPipelineControlPlane, TcpControlChannelExcludedDataPlaneUntouched) {
    constexpr std::uint16_t kControlPort = 30700;
    std::size_t ipv4_events = 0;
    tc8::dissect::PacketPipeline pipe([&](const tc8::CapturedEvent &ev) {
        if (std::holds_alternative<tc8::Ipv4Frame>(ev)) {
            ++ipv4_events;
        }
    });
    pipe.setControlPlanePort(kControlPort);
    feed(pipe, 1000, tcpEth(kDutMac, kTesterMac, kTesterIp, kDutIp, 45000, kControlPort, 1, 0,
                            /*syn=*/true, /*ack_flag=*/false, /*psh=*/false));
    feed(pipe, 2000, udpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, 20001, 20000, {0x02}));

    EXPECT_EQ(pipe.controlPlaneFrames(), 1u);
    EXPECT_EQ(ipv4_events, 1u);
}

// Stimulus markers (tc8/stimulus_marker.h): a registered acknowledgement is
// delivered by NAME at its own position among the captured frames — after every
// frame captured before it, before every frame captured after it. That position is
// the whole contract: it is what lets an absence case stop grading the DUT's
// traffic while a precondition was still being applied.
namespace {

// Matches a UT reply carrying `first_byte` as the first UDP payload byte.
tc8::StimulusMarkers::Matcher replyStartingWith(std::uint8_t first_byte) {
    return [first_byte](const std::uint8_t *frame, std::size_t len) {
        constexpr std::size_t kPayload = 14 + 20 + 8;
        return len > kPayload && frame[kPayload] == first_byte;
    };
}

}  // namespace

TEST(PacketPipelineStimulusMarker, DeliveredAtTheAcknowledgementsPositionOnce) {
    tc8::StimulusMarkers::reset();
    constexpr std::uint16_t kControlPort = 30600;
    std::vector<std::string> order;
    tc8::dissect::PacketPipeline pipe([&](const tc8::CapturedEvent &ev) {
        if (const auto *f = std::get_if<tc8::UdpFrame>(&ev)) {
            order.push_back("udp:" + std::to_string(f->src_port));
        }
    });
    pipe.setControlPlanePort(kControlPort);
    pipe.setStimulusMarkerListener([&](const std::string &name) { order.push_back("mark:" + name); });
    tc8::StimulusMarkers::expect("static_entry_add", replyStartingWith(0x97));

    const auto ack = udpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, kControlPort, 45000, {0x97, 0x05, 0x00});
    feed(pipe, 1000, udpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, 20001, 20000, {0x01}));
    feed(pipe, 1100, ack);
    feed(pipe, 1200, udpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, 20002, 20000, {0x02}));
    // A second, identical acknowledgement is not a second application.
    feed(pipe, 1300, ack);

    EXPECT_EQ(order, (std::vector<std::string>{"udp:20001", "mark:static_entry_add", "udp:20002"}));
    // Still withheld as frames — the marker carries the meaning, not the frame.
    EXPECT_EQ(pipe.controlPlaneFrames(), 2u);
}

// A step the DUT refused is withdrawn by its sender, and then no marker comes —
// a case must never open its window on a precondition that was not applied.
TEST(PacketPipelineStimulusMarker, AWithdrawnExpectationYieldsNothing) {
    tc8::StimulusMarkers::reset();
    constexpr std::uint16_t kControlPort = 30600;
    std::vector<std::string> marks;
    tc8::dissect::PacketPipeline pipe([](const tc8::CapturedEvent &) {});
    pipe.setControlPlanePort(kControlPort);
    pipe.setStimulusMarkerListener([&](const std::string &name) { marks.push_back(name); });
    const auto token = tc8::StimulusMarkers::expect("refused_step", replyStartingWith(0x97));
    tc8::StimulusMarkers::withdraw(token);

    feed(pipe, 1000, udpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, kControlPort, 45000, {0x97, 0x05, 0x07}));
    EXPECT_TRUE(marks.empty());
}

// Only withheld control-plane packets are consulted: the same bytes on a data
// port are traffic under test, never an acknowledgement.
TEST(PacketPipelineStimulusMarker, NeverCutFromTrafficUnderTest) {
    tc8::StimulusMarkers::reset();
    std::vector<std::string> marks;
    tc8::dissect::PacketPipeline pipe([](const tc8::CapturedEvent &) {});
    pipe.setControlPlanePort(30600);
    pipe.setStimulusMarkerListener([&](const std::string &name) { marks.push_back(name); });
    tc8::StimulusMarkers::expect("static_entry_add", replyStartingWith(0x97));

    feed(pipe, 1000, udpEth(kTesterMac, kDutMac, kDutIp, kTesterIp, 20001, 20000, {0x97, 0x05, 0x00}));
    EXPECT_TRUE(marks.empty());
    tc8::StimulusMarkers::reset();
}
