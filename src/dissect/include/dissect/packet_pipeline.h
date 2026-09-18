#pragma once

#include <cstdint>
#include <functional>

#include <pcap/pcap.h>
#include <tins/tcp_ip/stream_follower.h>

#include "tc8/captured_event.h"

#include "dissect/someip_dispatcher.h"

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

    // The harness's own DUT-control channel — the Tier-2 seam's request/response
    // traffic — rides the same wire as the protocol under test. Naming its
    // transport port here makes the pipeline drop the whole packet BEFORE it
    // emits any `CapturedEvent`, so no state machine can grade a control frame in
    // place of the traffic its case exists to observe.
    //
    // The defect this closes: `dispatchUdpFrame` raises `Udp_observed` for EVERY
    // UdpFrame, so the SCXML grades whichever datagram moves the machine first. A
    // control response landing inside the listen window is graded in place of the
    // case's own datagram, which arrives microseconds later and is never
    // considered. `BpfGroup::Tcp` never had this exposure only because
    // `dispatchTcpFrame` discards non-TcpFrame events by type; UDP has no such
    // discriminator, so the same property has to be restored by port.
    //
    // Why here and not in each case's dispatch: one packet fans out into more
    // than one alternative (every IPv4 packet also emits an `Ipv4Frame`, which
    // carries no transport ports and therefore cannot be classified downstream at
    // all). Deciding once per packet is the only place the rule holds for every
    // alternative uniformly.
    //
    // Why here and not in the kernel BPF: `bpf::tcp()` deliberately admits
    // `udp and port 30600` so `decode-pcap` can render the stimulus envelope into
    // the site timeline. Dropping here keeps that evidence intact — the CLI's
    // `pcap_dump` runs BEFORE `processFrame`, so a packet dropped here is still
    // in the saved pcap. Narrowing the BPF instead would have bought the verdict
    // fix by giving up the observability that comment argues for.
    //
    // Limit, stated rather than hidden: classification is by transport port, so
    // ARP traffic the control channel PROVOKES — the DUT resolving the tester
    // before it can answer — is indistinguishable from ARP under test and is NOT
    // dropped. That exposure is handled where it arises: the capability probe is
    // sourced from the tester alias, and a backend-static capability answer
    // avoids the probe entirely (`IDutControl::staticCapabilities`).
    //
    // 0 (the default) disables the drop, which is what every non-grading caller
    // wants — `decode-pcap` leaves it unset on purpose: it renders, it does not
    // grade, and a rendered timeline missing its own control exchange would be
    // less useful, not more.
    void setControlPlanePort(std::uint16_t port) noexcept { control_plane_port_ = port; }

    // Packets dropped by `setControlPlanePort`. Run-level for the same reason as
    // `truncatedFrames()`: the control channel is a property of the run, not of
    // one interface. Zero on a run whose cases never drove the seam.
    std::uint64_t controlPlaneFrames() const noexcept { return control_plane_frames_; }

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
    // See setControlPlanePort(). 0 = this caller grades nothing, or has no
    // control channel to exclude, so every packet reaches the listener.
    std::uint16_t control_plane_port_ = 0;
    std::uint64_t control_plane_frames_ = 0;
    // Arrival timestamp (us, epoch) of the packet currently being processed,
    // stashed so the TCP stream-follower callbacks (which fire synchronously
    // inside follower_.process_packet) can stamp the reassembled Transport —
    // the reliable-transport twin of the UDP path's inline t.observed_ts_us.
    std::int64_t last_packet_ts_us_ = 0;
};

}  // namespace tc8::dissect
