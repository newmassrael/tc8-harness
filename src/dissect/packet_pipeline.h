#pragma once

#include <cstdint>
#include <functional>

#include <pcap/pcap.h>
#include <tins/tcp_ip/stream_follower.h>

#include "tc8/captured_event.h"

#include "someip_dispatcher.h"

namespace tc8::dissect {

// L2 through application-protocol pipeline. Accepts raw libpcap frames
// with the capture datalink type, decodes whichever protocol the frame
// carries, and emits a `tc8::CapturedEvent` variant to the listener.
//
// Each test case registers which `tc8::BpfGroup` bucket it needs; the
// CLI sets the kernel BPF accordingly so the pipeline only sees the
// frames relevant to the active case. Per-case dispatch (in the
// `TestCaseTraits<SM>::dispatch` function) then pattern-matches on the
// variant and ignores whatever it doesn't care about.
//
// Protocol coverage currently implemented: SOME/IP (§5.1). Other
// groups (ARP §4.2, ICMPv4 §4.3, IPv4 §4.4/§4.5, UDP §4.6, DHCPv4 §4.7,
// TCP §4.8) have `CapturedEvent` alternatives reserved; their decoders
// are filled in alongside the first case in each section.
class PacketPipeline {
public:
    using Listener = std::function<void(const ::tc8::CapturedEvent &)>;

    explicit PacketPipeline(Listener listener);

    void processFrame(const pcap_pkthdr &hdr, const std::uint8_t *bytes, int datalink_type);

    // libpcap's `pcap_pkthdr::ts.tv_usec` carries microseconds when the
    // capture handle was opened with the default precision and
    // nanoseconds when opened with `PCAP_TSTAMP_PRECISION_NANO`
    // (`pcap_open_offline_with_tstamp_precision` uses NANO for the
    // smoke-test forensic-replay path). The TCP-frame timestamp surface
    // (`TcpFrame::observed_ts_us`) wants microseconds, so callers
    // wire the source's precision in here once at construction; the
    // dissector divides by 1000 when NANO. Default
    // `PCAP_TSTAMP_PRECISION_MICRO=0` keeps the behaviour right for
    // any caller that forgets to set this.
    void setTstampPrecision(int precision) noexcept { tstamp_precision_ = precision; }

private:
    void onNewStream(Tins::TCPIP::Stream &stream);
    void onClientData(Tins::TCPIP::Stream &stream);
    void onServerData(Tins::TCPIP::Stream &stream);

    Listener listener_;
    SomeIpDispatcher dispatcher_;
    Tins::TCPIP::StreamFollower follower_;
    int tstamp_precision_ = PCAP_TSTAMP_PRECISION_MICRO;
};

}  // namespace tc8::dissect
