#include "cli/liveness_anchor.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#include <poll.h>

#include <tins/arp.h>
#include <tins/ethernetII.h>
#include <tins/exceptions.h>
#include <tins/icmp.h>
#include <tins/ip.h>

#include "capture/pcap_source.h"
#include "stimulus/arp_builder.h"
#include "stimulus/icmpv4_builder.h"
#include "stimulus/iface_addr.h"

namespace tc8::cli {

namespace {

// Echo identifier of the anchor's Request: distinct from the identifier the
// ICMPv4 cases put on the wire (kIcmpEchoId), so a late reply to a case's own
// Request is never taken for the anchor's answer.
constexpr std::uint16_t kAnchorEchoId = 0xA7C8;

// Two attempts, so one lost probe or reply costs a retry rather than the
// conclusion; each waits long enough for a loaded host to answer an ARP Request
// or an Echo Request, which no conformant stack defers.
constexpr int kAttempts = 2;
constexpr std::chrono::milliseconds kAttemptBound{500};

// Only the anchor's reply kind is let through the anchor's own handle; the
// predicate below decides whether a frame is the answer.
constexpr const char *kArpFilter = "arp or (vlan and arp)";
constexpr const char *kIcmpFilter = "icmp or (vlan and icmp)";

struct Probe {
    std::vector<std::uint8_t> frame;
    std::uint16_t echo_seq = 0;
};

Probe buildProbe(sce::LivenessAnchorKind kind, const std::array<std::uint8_t, 6> &tester_mac,
                 const ::tc8::TestConfig &cfg, int attempt) {
    Probe p;
    if (kind == sce::LivenessAnchorKind::kArpExchange) {
        // The tester's real interface MAC, not the injected placeholder the ARP
        // cases use: the DUT records the sender of a Request, and a placeholder
        // there would leave the tester's address bound to a MAC nobody holds.
        p.frame = ::tc8::stimulus::buildArpRequest(tester_mac, cfg.tester.ip, cfg.dut.ip);
        return p;
    }
    ::tc8::stimulus::IcmpMessageSpec spec;
    spec.src_mac = tester_mac;
    if (cfg.dut.mac != std::array<std::uint8_t, 6>{}) {
        spec.dst_mac = cfg.dut.mac;
    }
    spec.src_ip = cfg.tester.ip;
    spec.dst_ip = cfg.dut.ip;
    spec.echo_id = kAnchorEchoId;
    spec.echo_seq = static_cast<std::uint16_t>(attempt + 1);
    p.echo_seq = spec.echo_seq;
    p.frame = ::tc8::stimulus::buildIcmpMessage(spec);
    return p;
}

// Whether a captured frame is the DUT's answer to `probe`. Addresses compare in
// the network-byte-order form the config carries, as the packet pipeline does.
bool isAnswer(sce::LivenessAnchorKind kind, const ::tc8::TestConfig &cfg, const Probe &probe,
              const u_char *data, std::uint32_t len) {
    try {
        Tins::EthernetII eth(data, len);
        if (kind == sce::LivenessAnchorKind::kArpExchange) {
            const auto *arp = eth.find_pdu<Tins::ARP>();
            return arp != nullptr && arp->opcode() == Tins::ARP::REPLY &&
                   static_cast<std::uint32_t>(arp->sender_ip_addr()) == cfg.dut.ip &&
                   static_cast<std::uint32_t>(arp->target_ip_addr()) == cfg.tester.ip;
        }
        const auto *ip = eth.find_pdu<Tins::IP>();
        const auto *icmp = eth.find_pdu<Tins::ICMP>();
        return ip != nullptr && icmp != nullptr &&
               static_cast<std::uint32_t>(ip->src_addr()) == cfg.dut.ip &&
               icmp->type() == Tins::ICMP::ECHO_REPLY && icmp->id() == kAnchorEchoId &&
               icmp->sequence() == probe.echo_seq;
    } catch (const Tins::exception_base &) {
        return false;
    }
}

}  // namespace

LivenessAnchorRun runLivenessAnchor(std::string_view iface, const ::tc8::TestConfig &cfg,
                                    sce::DutRequirements under_test) {
    LivenessAnchorRun run;
    run.kind = sce::selectLivenessAnchor(under_test);
    run.shared_requirements = under_test.sharedWith(sce::exercisedBy(run.kind));
    if (cfg.dut.ip == 0 || cfg.tester.ip == 0) {
        run.outcome = sce::LivenessAnchorOutcome::kNoDutAddress;
        return run;
    }
    const auto tester_mac = ::tc8::stimulus::macOfInterface(iface);
    if (!tester_mac) {
        run.outcome = sce::LivenessAnchorOutcome::kUnavailable;
        return run;
    }

    // Opened and filtered before the first probe leaves, so an answer that
    // arrives at once is already in this handle's ring.
    std::unique_ptr<capture::PcapSource> tap;
    try {
        constexpr int kSnaplen = 256;
        constexpr int kRingBytes = 256 * 1024;
        tap = capture::PcapSource::openLive(iface, kSnaplen, /*read_timeout_ms=*/10, kRingBytes);
        tap->applyBpf(run.kind == sce::LivenessAnchorKind::kArpExchange ? kArpFilter : kIcmpFilter);
    } catch (const std::exception &) {
        run.outcome = sce::LivenessAnchorOutcome::kUnavailable;
        return run;
    }

    for (int attempt = 0; attempt < kAttempts; ++attempt) {
        const Probe probe = buildProbe(run.kind, *tester_mac, cfg, attempt);
        ++run.attempts;
        const auto sent_at = std::chrono::steady_clock::now();
        if (::tc8::stimulus::sendRawEthernet(probe.frame, iface) != 0) {
            run.outcome = sce::LivenessAnchorOutcome::kUnavailable;
            return run;
        }
        const auto deadline = sent_at + kAttemptBound;
        bool answered = false;
        while (!answered && std::chrono::steady_clock::now() < deadline) {
            const int n = tap->dispatch(-1, [&](const pcap_pkthdr &hdr, const u_char *data) {
                if (!answered && isAnswer(run.kind, cfg, probe, data, hdr.caplen)) {
                    answered = true;
                }
            });
            if (n < 0) {
                run.outcome = sce::LivenessAnchorOutcome::kUnavailable;
                return run;
            }
            if (!answered && n == 0) {
                pollfd pfd{tap->selectableFd(), POLLIN, 0};
                ::poll(&pfd, pfd.fd >= 0 ? 1 : 0, 10);
            }
        }
        if (answered) {
            run.outcome = sce::LivenessAnchorOutcome::kAnswered;
            run.latency_us = static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(
                                                   std::chrono::steady_clock::now() - sent_at)
                                                   .count());
            return run;
        }
    }
    run.outcome = sce::LivenessAnchorOutcome::kUnanswered;
    return run;
}

}  // namespace tc8::cli
