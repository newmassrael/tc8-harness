#include "pcap_source.h"

#include <stdexcept>
#include <string>

namespace tc8::capture {

std::unique_ptr<PcapSource> PcapSource::openLive(std::string_view iface, int snaplen, int read_timeout_ms) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    // pcap_create + buffer-size + activate path so the TPACKET kernel
    // ring is provisioned large enough to absorb the entire stimulus
    // burst before the post-stimulus dispatch loop starts draining.
    // Default ring is system-dependent and has been observed to drop
    // newest arrivals once full — visible empirically on §4.8 multi-
    // phase active-OPEN cases (5 phases × ~5 frames each over ~6 s of
    // blocking stimulus). 16 MB is a generous upper bound; even
    // 65535-byte snapshots × tens of thousands of frames fit.
    pcap_t *h = pcap_create(std::string(iface).c_str(), errbuf);
    if (!h) {
        throw std::runtime_error("pcap_create failed: " + std::string(errbuf));
    }
    pcap_set_snaplen(h, snaplen);
    pcap_set_promisc(h, 1);
    pcap_set_timeout(h, read_timeout_ms);
    pcap_set_buffer_size(h, 16 * 1024 * 1024);
    if (pcap_activate(h) < 0) {
        const std::string msg = "pcap_activate failed: " + std::string(pcap_geterr(h));
        pcap_close(h);
        throw std::runtime_error(msg);
    }
    // Force non-blocking dispatch. The pcap(3) read timeout "cannot be
    // guaranteed; some implementations may always return immediately, while
    // others may not return until a packet arrives" (libpcap manpage). On
    // Linux TPACKET this manifests as pcap_dispatch() blocking on poll()
    // forever when no BPF-matching frame arrives — fatal for absence-pattern
    // cases (e.g. §4.2.4.2 ARP_21/27/37/42) whose SCXML deadline can only
    // fire when TestRunner::tick() runs, which happens only AFTER each
    // dispatch returns. Non-blocking + explicit caller-side sleep makes the
    // tick cadence independent of ambient traffic.
    if (pcap_setnonblock(h, 1, errbuf) < 0) {
        const std::string msg = "pcap_setnonblock failed: " + std::string(errbuf);
        pcap_close(h);
        throw std::runtime_error(msg);
    }
    return std::unique_ptr<PcapSource>(new PcapSource(h, /*offline=*/false));
}

std::unique_ptr<PcapSource> PcapSource::openOffline(const std::filesystem::path &file) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t *h = pcap_open_offline_with_tstamp_precision(file.c_str(), PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (!h) {
        throw std::runtime_error("pcap_open_offline failed: " + std::string(errbuf));
    }
    return std::unique_ptr<PcapSource>(new PcapSource(h, /*offline=*/true));
}

PcapSource::~PcapSource() {
    if (handle_) {
        pcap_close(handle_);
    }
}

void PcapSource::applyBpf(std::string_view expression) {
    bpf_program prog{};
    if (pcap_compile(handle_, &prog, std::string(expression).c_str(),
                     /*optimize=*/1, PCAP_NETMASK_UNKNOWN) < 0) {
        throw std::runtime_error("pcap_compile failed: " + std::string(pcap_geterr(handle_)));
    }
    const int rc = pcap_setfilter(handle_, &prog);
    pcap_freecode(&prog);
    if (rc < 0) {
        throw std::runtime_error("pcap_setfilter failed: " + std::string(pcap_geterr(handle_)));
    }
}

int PcapSource::dispatch(int max_frames, const FrameCallback &cb) {
    return pcap_dispatch(
        handle_, max_frames,
        [](u_char *user, const pcap_pkthdr *h, const u_char *bytes) {
            const auto *cb_ptr = reinterpret_cast<const FrameCallback *>(user);
            (*cb_ptr)(*h, bytes);
        },
        const_cast<u_char *>(reinterpret_cast<const u_char *>(&cb)));
}

}  // namespace tc8::capture
