#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>

#include <pcap/pcap.h>
#include <tins/tcp_ip/stream_follower.h>

#include "tc8/captured_event.h"
#include "tc8/dissection_stats.h"
#include "tc8/wire/ethernet_frame.h"
#include "tc8/wire/ipv4_header.h"
#include "tc8/wire/tcp_segment.h"

#include "dissect/someip_dispatcher.h"

namespace tc8::dissect {

// L2 through application-protocol pipeline. Accepts raw libpcap frames
// with the capture datalink type, decodes whichever protocol the frame
// carries, and emits a `tc8::CapturedEvent` variant to the listener.
//
// Every layer through TCP is read by the harness's own decoders (tc8/wire/,
// docs/tech-debt.md TD-69), which read every input their RFC allows. libtins
// is kept only as the TCP stream reassembler for SOME/IP over TCP, and is
// handed segments built from the decoded fields, not the captured bytes.
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

    // Dissect one captured frame. Every frame leaves a count in
    // `dissectionStats()`: none is dropped without one.
    void processFrame(const pcap_pkthdr &hdr, const std::uint8_t *bytes, int datalink_type);

    // What became of every frame this run handed in (tc8/dissection_stats.h).
    //
    // TRUNCATED. The dissector parses `hdr.caplen` bytes and every offset/length
    // check below is written against that, so a frame longer than the snaplen would
    // not fail — it would parse SHORT and yield a plausible, wrong decode: a
    // truncated TCP payload reads as a smaller segment, a cut option list as a
    // shorter one. That is a fabricated observation, which is worse than a dropped
    // frame (a drop is at least an absence). So the frame is refused here, once,
    // for every caller — the live capture loop and `decode-pcap` replaying a saved
    // file alike. Run-level, not per-source, because the snaplen is a property of
    // the run: both capture sources are opened with the same one. Non-zero means
    // the capture cannot represent the wire — today's snaplen is 65535 while a GSO
    // super-frame can reach 65536+, so this is reachable wherever segmentation
    // offload is on (the netns veths cap it; an externally-owned interface may not).
    //
    // UNDISSECTABLE. The frame is whole and a decoder could not read it. Counted
    // twice: every such frame, and those that could have been the DUT's (its
    // Ethernet source is the DUT's MAC, or the run named no DUT MAC to tell; see
    // `setDutMac`). Only the second count is an observation gap. The tester sends
    // malformed frames on purpose (a header the DUT must discard), and the capture
    // sees them too; the tester knows what it sent, so an unreadable copy of its own
    // stimulus hides nothing about the DUT.
    //
    // CONSUMER FAULT. The frame was read and the listener (the case's state machine)
    // threw on an event made from it. Counted apart from the two above because it is
    // not a property of the frame: the event was lost by the harness, not the wire.
    const ::tc8::DissectionStats &dissectionStats() const noexcept { return stats_; }

    // The DUT's MAC (over-the-wire order), so an undissectable frame can be told
    // apart from the tester's own malformed stimulus by its Ethernet source. All
    // zero (the default) means the run did not name one: every undissectable frame
    // then counts as possibly the DUT's, which can cost a conclusion but never
    // forge one.
    void setDutMac(const std::array<std::uint8_t, 6> &mac) noexcept { dut_mac_ = mac; }

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
    // dropped. It cannot be, by any key: on single-pc the control peer IS the
    // tester address the ARP cases grade, so withholding "ARP for the control
    // peer" would withhold the very frame an absence case asserts and pass it
    // vacuously. That exposure is handled where it arises: the capability probe is
    // sourced from the tester alias, a backend-static capability answer avoids the
    // probe entirely (`IDutControl::staticCapabilities`), and a case whose
    // precondition is itself a control request opens its grading window at that
    // request's acknowledgement — `setStimulusMarkerListener` below.
    //
    // 0 (the default) disables the drop, which is what every non-grading caller
    // wants — `decode-pcap` leaves it unset on purpose: it renders, it does not
    // grade, and a rendered timeline missing its own control exchange would be
    // less useful, not more.
    void setControlPlanePort(std::uint16_t port) noexcept { control_plane_port_ = port; }

    // Packets dropped by `setControlPlanePort`. Run-level for the same reason as
    // the truncation count: the control channel is a property of the run, not of
    // one interface. Zero on a run whose cases never drove the seam.
    std::uint64_t controlPlaneFrames() const noexcept { return control_plane_frames_; }

    // Called with a stimulus's name when a withheld control-plane frame is that
    // stimulus's acknowledgement (`tc8::StimulusMarkers`) — at the frame's own
    // position in capture order, which is the point of it: every frame the
    // listener received before this call was emitted before the step took
    // effect. Only packets `setControlPlanePort` withholds are consulted, so a
    // run with no control port set never produces a marker.
    using MarkerListener = std::function<void(const std::string &name)>;
    void setStimulusMarkerListener(MarkerListener listener) {
        marker_listener_ = std::move(listener);
    }

private:
    void onNewStream(Tins::TCPIP::Stream &stream);
    void onClientData(Tins::TCPIP::Stream &stream);
    void onServerData(Tins::TCPIP::Stream &stream);
    // The per-layer dissection of one whole frame, by the harness's own decoders
    // (tc8/wire/). Each emits its events to the listener, or counts the frame as
    // undissectable where its header cannot be located.
    void dissectFrame(const pcap_pkthdr &hdr, const std::uint8_t *bytes, std::uint64_t frame_idx,
                      std::int64_t observed_ts_us);
    void dissectIcmp(const pcap_pkthdr &hdr, const std::uint8_t *bytes, std::uint64_t frame_idx,
                     const ::tc8::wire::Ipv4Header &ip, const std::uint8_t *l4, std::size_t l4_len,
                     const ::tc8::Dot1QTag &vlan, std::int64_t observed_ts_us);
    void dissectUdp(const pcap_pkthdr &hdr, const std::uint8_t *bytes, std::uint64_t frame_idx,
                    const ::tc8::wire::EthernetFrame &eth, const ::tc8::wire::Ipv4Header &ip,
                    const std::uint8_t *l4, std::size_t l4_len, const ::tc8::Dot1QTag &vlan,
                    std::int64_t observed_ts_us);
    void dissectTcp(const pcap_pkthdr &hdr, const std::uint8_t *bytes, std::uint64_t frame_idx,
                    const ::tc8::wire::Ipv4Header &ip, const std::uint8_t *l4, std::size_t l4_len,
                    const ::tc8::Dot1QTag &vlan, std::int64_t observed_ts_us);
    void followTcp(const ::tc8::wire::Ipv4Header &ip, const ::tc8::wire::TcpSegment &tcp);
    void noteUndissectable(const pcap_pkthdr &hdr, const std::uint8_t *bytes, std::uint64_t frame_idx,
                           const char *reason);

    Listener listener_;
    SomeIpDispatcher dispatcher_;
    Tins::TCPIP::StreamFollower follower_;
    int tstamp_precision_ = PCAP_TSTAMP_PRECISION_MICRO;

    // See dissectionStats(). Counted, never reset — it describes the run.
    ::tc8::DissectionStats stats_;
    // See setDutMac(). All zero = not named.
    std::array<std::uint8_t, 6> dut_mac_{};
    // See setControlPlanePort(). 0 = this caller grades nothing, or has no
    // control channel to exclude, so every packet reaches the listener.
    std::uint16_t control_plane_port_ = 0;
    std::uint64_t control_plane_frames_ = 0;
    // See setStimulusMarkerListener(). Empty = markers are not wanted.
    MarkerListener marker_listener_;
    // Arrival timestamp (us, epoch) of the packet currently being processed,
    // stashed so the TCP stream-follower callbacks (which fire synchronously
    // inside follower_.process_packet) can stamp the reassembled Transport —
    // the reliable-transport twin of the UDP path's inline t.observed_ts_us.
    std::int64_t last_packet_ts_us_ = 0;
};

}  // namespace tc8::dissect
