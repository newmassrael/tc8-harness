#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <pcap/pcap.h>

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

    bool isOffline() const {
        return offline_;
    }

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
    PcapSource(pcap_t *h, bool offline) : handle_(h), offline_(offline) {}

    pcap_t *handle_;
    bool offline_;
};

}  // namespace tc8::capture
