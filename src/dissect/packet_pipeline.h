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
// groups (ARP §4.2, ICMPv4 §4.3, IPv4 §4.4 / §4.5, UDP §4.6, DHCPv4 §4.7,
// TCP §4.8) have `CapturedEvent` alternatives reserved; their decoders
// are filled in alongside the first case in each section.
class PacketPipeline {
public:
    using Listener = std::function<void(const ::tc8::CapturedEvent &)>;

    explicit PacketPipeline(Listener listener);

    // Dissect one captured frame. A frame the capture TRUNCATED
    // (`hdr.caplen < hdr.len`) is counted and dropped rather than dissected —
    // see `truncatedFrames()`.
    void processFrame(const pcap_pkthdr &hdr, const std::uint8_t *bytes, int datalink_type);

    // Frames this run refused because the capture did not retain all of them.
    //
    // The dissector parses `hdr.caplen` bytes and every offset/length check
    // below is written against that, so a frame longer than the snaplen would
    // not fail — it would parse SHORT and yield a plausible, wrong decode: a
    // truncated TCP payload reads as a smaller segment, a cut option list as a
    // shorter one. That is a fabricated observation, which is worse than a
    // dropped frame (a drop is at least an absence). So the frame is refused
    // here, once, for every caller — the live capture loop and `decode-pcap`
    // replaying a saved file alike.
    //
    // Run-level, not per-source, because the snaplen is a property of the run:
    // both capture sources are opened with the same one, so attributing a
    // truncation to an interface would add no information.
    //
    // Non-zero means the capture cannot represent the wire — today's snaplen is
    // 65535 while a GSO super-frame can reach 65536+, so this is reachable
    // wherever segmentation offload is on (the netns veths cap it; an
    // externally-owned interface may not).
    std::uint64_t truncatedFrames() const noexcept { return truncated_frames_; }

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

    // See truncatedFrames(). Counted, never reset — it describes the run.
    std::uint64_t truncated_frames_ = 0;
    // Arrival timestamp (us, epoch) of the packet currently being processed,
    // stashed so the TCP stream-follower callbacks (which fire synchronously
    // inside follower_.process_packet) can stamp the reassembled Transport —
    // the reliable-transport twin of the UDP path's inline t.observed_ts_us.
    std::int64_t last_packet_ts_us_ = 0;
};

}  // namespace tc8::dissect
