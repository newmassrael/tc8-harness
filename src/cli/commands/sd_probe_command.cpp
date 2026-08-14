#include "cli/sd_probe_command.h"

#include <poll.h>

#include <arpa/inet.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <thread>
#include <variant>

#include "tc8/captured_event.h"
#include "tc8/dut_config.h"
#include "tc8/someip/protocol.h"

#include "capture/bpf_filter.h"
#include "capture/multicast_membership.h"
#include "capture/pcap_source.h"
#include "cli/signal_handler.h"
#include "dissect/packet_pipeline.h"

namespace tc8::cli {

namespace {

// Idle quantum between dispatch passes, and the poll() timeout when the handle
// gives us a selectable fd. Same 20 ms the case loop uses: short enough that the
// probe's own deadline is honoured to within one quantum, long enough that a
// quiet wire costs no measurable CPU. A frame arriving mid-wait wakes poll()
// immediately, so the value bounds latency only on a wire with no traffic.
constexpr int kIdleWaitMs = 20;

}  // namespace

SdProbeCommand::SdProbeCommand(CLI::App &app) {
    sub_ = app.add_subcommand(
        "sd-probe",
        "Observe whether the DUT's SOME/IP-SD reaches the tester (passive)");
    sub_->add_option("-i,--interface", iface_, "Tester NIC to listen on")->required();
    sub_->add_option("--dut-ip", dut_ip_, "DUT IPv4 address — only SD from this source counts")
        ->required();
    sub_->add_option("--sd-group", sd_group_,
                     "SD multicast group the DUT offers on (default: the "
                     "compiled-in 224.244.224.245). Set it when the site's "
                     "vsomeip.json pins another group — the probe both joins "
                     "and asserts on this address.");
    sub_->add_option("--port", port_, "SD UDP port (default: protocol constant 30490)");
    sub_->add_option("-t,--timeout", timeout_ms_,
                     "How long to listen, in milliseconds, before concluding "
                     "nothing arrived")
        ->capture_default_str();
    sub_->add_option("--ready-file", ready_file_,
                     "Create this file once the capture is armed and the SD "
                     "group is held, so a launcher starts the DUT only after "
                     "its first frame can be observed. Empty = disabled.");
    sub_->add_flag("!--no-multicast-membership", multicast_membership_,
                   "Do not hold an IGMP membership for the SD group. Without "
                   "it a snooping bridge may prune the group before the "
                   "capture, so a silent window no longer implicates the DUT — "
                   "the probe then reports 'could not run' instead of 'not "
                   "observed'.");
}

int SdProbeCommand::run() {
    in_addr dut_addr{};
    if (::inet_pton(AF_INET, dut_ip_.c_str(), &dut_addr) != 1) {
        std::fprintf(stderr, "sd-probe: invalid DUT IPv4 address '%s'\n", dut_ip_.c_str());
        return kCouldNotRun;
    }
    const std::string group = sd_group_.empty() ? std::string(::tc8::dut::kSdMcastGroup) : sd_group_;
    in_addr group_addr{};
    if (::inet_pton(AF_INET, group.c_str(), &group_addr) != 1) {
        std::fprintf(stderr, "sd-probe: invalid SD multicast group '%s'\n", group.c_str());
        return kCouldNotRun;
    }
    const auto port = port_ > 0 ? static_cast<std::uint16_t>(port_) : ::tc8::dut::kSdPort;

    // Narrow in the kernel to SD-port traffic sourced by the DUT; the decode
    // below still confirms the frame really carries the SD Message ID, so a
    // foreign protocol squatting on the port cannot be mistaken for a DUT that
    // is discovering. VLAN-wrapped like every other capture filter — an
    // 802.1Q-tagged wire must not read as a silent one.
    const std::string bpf = capture::bpf::vlanAware(
        "src host " + dut_ip_ + " and udp port " + std::to_string(port));

    std::unique_ptr<capture::PcapSource> src;
    try {
        src = capture::PcapSource::openLive(iface_, /*snaplen=*/65535, kIdleWaitMs);
        src->applyBpf(bpf);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "sd-probe: cannot capture on '%s': %s\n", iface_.c_str(), e.what());
        return kCouldNotRun;
    }
    SignalGuard guard(*src);

    // Hold the group for exactly as long as we listen. Joined BEFORE the ready
    // signal, so a launcher that waits for it cannot start a DUT whose first
    // Offer is still being pruned.
    auto membership = multicast_membership_
                          ? capture::MulticastMembership::join(iface_, {group})
                          : capture::MulticastMembership::declined({group});
    for (const auto &f : membership.failed()) {
        std::fprintf(stderr, "sd-probe: multicast membership on %s failed: %s\n", iface_.c_str(),
                     f.c_str());
    }
    std::printf("sd-probe: listening on %s for SOME/IP-SD from %s (group %s, %s)\n", iface_.c_str(),
                dut_ip_.c_str(), group.c_str(), membership.allHeld() ? "held" : "NOT HELD");

    if (!ready_file_.empty()) {
        if (std::FILE *rf = std::fopen(ready_file_.c_str(), "wb")) {
            std::fclose(rf);
        } else {
            std::fprintf(stderr, "sd-probe: warning: could not create --ready-file '%s'\n",
                         ready_file_.c_str());
        }
    }

    // Counted separately because they answer different questions. Frames to the
    // group are the precondition every offer-observation verdict rests on;
    // frames the DUT sent elsewhere prove its SD is alive but not that the
    // tester can hear it discover, and an operator told only "no SD" would go
    // looking for a dead DUT instead of a multicast path.
    std::uint64_t sd_to_group = 0;
    std::uint64_t sd_elsewhere = 0;
    dissect::PacketPipeline pipeline([&](const ::tc8::CapturedEvent &ev) {
        const auto *f = std::get_if<::tc8::SomeIpFrame>(&ev);
        if (f == nullptr || f->service_id != ::tc8::someip::kSdServiceId) {
            return;
        }
        if (f->src_ip != dut_addr.s_addr) {
            return;  // the BPF already excludes this; the decode is the SSOT
        }
        if (f->dst_ip == group_addr.s_addr) {
            ++sd_to_group;
        } else {
            ++sd_elsewhere;
        }
    });
    pipeline.setTstampPrecision(src->tstampPrecision());

    // The window opens now, not at process start: everything above is setup the
    // caller did not ask us to spend its budget on.
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms_);
    const int fd = src->selectableFd();
    const int dlt = src->datalink();
    while (sd_to_group == 0 && !SignalGuard::stopRequested() &&
           std::chrono::steady_clock::now() < deadline) {
        const int n = src->dispatch(/*max_frames=*/-1,
                                    [&](const pcap_pkthdr &hdr, const u_char *data) {
                                        pipeline.processFrame(hdr, data, dlt);
                                    });
        if (n == -2) {
            break;  // pcap_breakloop — SIGINT/SIGTERM
        }
        if (n < 0) {
            std::fprintf(stderr, "sd-probe: dispatch error: %s\n", src->lastError());
            return kCouldNotRun;
        }
        if (n > 0) {
            continue;  // drain what is queued before sleeping again
        }
        if (fd >= 0) {
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLIN;
            // POLLIN, an error and EINTR all just re-run the loop, which
            // re-dispatches and re-checks the deadline — nothing to inspect.
            poll(&pfd, 1, kIdleWaitMs);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(kIdleWaitMs));
        }
    }

    if (sd_to_group > 0) {
        std::printf("sd-probe: observed %llu SD frame(s) from %s to %s\n",
                    static_cast<unsigned long long>(sd_to_group), dut_ip_.c_str(), group.c_str());
        return kObserved;
    }
    // Nothing on the group. Which conclusion that licenses depends on whether
    // the group was actually held — the same rule the capture axis states: only
    // a held membership makes "we heard nothing" a statement about the DUT.
    if (!membership.allHeld()) {
        std::fprintf(stderr,
                     "sd-probe: no SD frame from %s on %s, and the group %s was NOT held — "
                     "a snooping bridge may have pruned it before the capture, so this says "
                     "nothing about the DUT\n",
                     dut_ip_.c_str(), iface_.c_str(), group.c_str());
        return kCouldNotRun;
    }
    if (sd_elsewhere > 0) {
        std::fprintf(stderr,
                     "sd-probe: %llu SD frame(s) from %s arrived within %d ms but NONE was "
                     "addressed to %s — the DUT's SD is running; its multicast leg is not\n",
                     static_cast<unsigned long long>(sd_elsewhere), dut_ip_.c_str(), timeout_ms_,
                     group.c_str());
        return kNotObserved;
    }
    std::fprintf(stderr, "sd-probe: no SOME/IP-SD from %s on %s within %d ms\n", dut_ip_.c_str(),
                 iface_.c_str(), timeout_ms_);
    return kNotObserved;
}

}  // namespace tc8::cli
