#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <pcap/pcap.h>

#include "tc8/capture_stats.h"  // tc8::CaptureStats (neutral, libpcap-free leaf)

namespace tc8::capture {

class PcapSource {
public:
    using FrameCallback = std::function<void(const pcap_pkthdr &, const u_char *)>;

    static std::unique_ptr<PcapSource> openLive(std::string_view interface, int snaplen = 65535,
                                                int read_timeout_ms = 100);
    static std::unique_ptr<PcapSource> openOffline(const std::filesystem::path &file);

    ~PcapSource();
    PcapSource(const PcapSource &) = delete;
    PcapSource &operator=(const PcapSource &) = delete;

    void applyBpf(std::string_view expression);
    int dispatch(int max_frames, const FrameCallback &cb);

    void breakLoop() {
        pcap_breakloop(handle_);
    }

    int datalink() const {
        return pcap_datalink(handle_);
    }

    // A file descriptor the caller can poll()/select() for readability so the
    // capture loop can sleep on frame arrival instead of a fixed idle interval.
    // Returns the libpcap selectable fd for a live handle opened with immediate
    // mode (readable per-packet), or -1 when the platform/handle cannot supply
    // one (e.g. offline replay) — callers must fall back to a timed wait then.
    int selectableFd() const {
        return pcap_get_selectable_fd(handle_);
    }

    bool isOffline() const {
        return offline_;
    }

    // Frame accounting for this source since the handle was activated — the
    // per-run answer to "did the capture underlying the verdict lose frames?".
    // Cheap (one syscall-ish read of counters libpcap already maintains), so
    // the natural call site is teardown; there is no per-frame cost.
    //
    // Reports `available = false` rather than zeroes when the counters cannot be
    // had — see `tc8::CaptureStats::available`. Offline replay is rejected up
    // front because `pcap_stats` is documented to fail on a savefile: gating on
    // `offline_` states that as intent instead of leaning on the error return.
    ::tc8::CaptureStats stats() const;

    // libpcap timestamp precision for the underlying handle.
    // Returns `PCAP_TSTAMP_PRECISION_MICRO` (0) for live captures
    // (libpcap default) and `PCAP_TSTAMP_PRECISION_NANO` (1) for
    // offline replay opened via
    // `pcap_open_offline_with_tstamp_precision(... NANO ...)`.
    // Consumers (`PacketPipeline::setTstampPrecision`) need this so
    // the TCP-frame `observed_ts_us` surface stays in microseconds
    // regardless of the source's precision.
    int tstampPrecision() const {
        return pcap_get_tstamp_precision(handle_);
    }

    const char *lastError() const {
        return pcap_geterr(handle_);
    }

    // Raw libpcap handle. Exposed narrowly for ops that libpcap exposes
    // only through the pcap_t* (e.g. pcap_dump_open). Callers must not
    // close or replace the handle — the PcapSource owns its lifetime.
    pcap_t *handle() const {
        return handle_;
    }

private:
    PcapSource(pcap_t *h, bool offline, std::string iface)
        : handle_(h), offline_(offline), iface_(std::move(iface)) {}

    pcap_t *handle_;
    bool offline_;
    // The source `stats()` attributes its counters to. Held here because
    // libpcap does not hand the device name back from an activated handle, and
    // a multi-source run must say WHICH interface dropped.
    std::string iface_;
};

}  // namespace tc8::capture
