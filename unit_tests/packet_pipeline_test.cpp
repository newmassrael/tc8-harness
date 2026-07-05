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

#include "dissect/packet_pipeline.h"
#include "tc8/captured_event.h"

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
