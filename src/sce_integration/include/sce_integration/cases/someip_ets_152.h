#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_152_sm.h"

namespace tc8::sce::cases {

using SomeipEts152SM = ::SCE::Generated::someip_ets_152::someip_ets_152;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_152 — SD_Session_ID_is_one_after_wrapping.
// Per PRS_SOMEIPSD_00159 the DUT's outgoing SD session_id increments
// per emitted SD entry and on wrap MUST skip 0, restarting at 1. The
// stimulus bursts SubscribeEventgroup (eg 0x0002) on a background
// thread so vsomeip's outgoing counter climbs at ~480 acks/sec; the
// 65,535 wrap is reachable in ~140 s. Detached thread terminates on
// process exit (verdict-reach short-circuit) — same precedent as
// §5.1.6 ETS_084's accepted-fd holder thread.
template <>
struct TestCaseTraits<cases::SomeipEts152SM> : SomeIpAnyBase<cases::SomeipEts152SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_152";
    static constexpr std::string_view kDescription =
        "Burst Subscribe → observe DUT SD session_id wrap 0xFFFF → 0x0001";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // FindService boot first so phase 1 fires on a fresh OfferService.
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        // Pre-build the Subscribe datagram once. Carries:
        //   - eg 0x0002 (configured eventgroup; option-walker passes the
        //     unknown-eg gate so the DUT actually emits an Ack).
        //   - sd_flags=0x40 (Unicast=1, Reboot=0). Default 0xC0 sets
        //     Reboot bit on every emit, which trips vsomeip's reboot-
        //     detection at sdi::process_eventgroupentry → expire all
        //     active subscriptions → no Ack emit → counter doesn't climb.
        //   - tester_endpoint pre-filled (ipv4_be + port + l4proto).
        //     Default 0.0.0.0 trips vsomeip's "Subscriber's IP isn't in
        //     the same subnet" gate. emitSubscribeEventgroupRaw's auto-
        //     fill SKIPS port + l4proto when ipv4 is non-zero, so caller
        //     must populate all three.
        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id   = 0x0002;
        params.session_id             = 0x0001;
        params.sd_flags               = 0x40;
        params.tester_endpoint.ipv4_be = cfg.ipv4.tester_ip;
        params.tester_endpoint.port    = tc8::dut::kSdPort;
        params.tester_endpoint.l4proto = 0x11;  // UDP
        const auto datagram = ::tc8::stimulus::buildSubscribeEventgroup(params);

        // Burst loop on a detached thread so kickStimulus returns at
        // once and the harness poll loop / SCXML observe SD frames in
        // real time. 100k bursts × 1.5 ms pacing ≈ 150 s wall — enough
        // headroom over the ~140 s wrap window. Process exit on verdict
        // reach reaps the thread; partial-emit at exit is acceptable
        // because the test asserts wire observation, not burst completion.
        const std::uint32_t dut_ip   = cfg.ipv4.dut_iface_ip;
        const std::uint32_t tester_ip = cfg.ipv4.tester_ip;
        std::thread([datagram, dut_ip, tester_ip]() {
            const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) return;
            const int reuse = 1;
            ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

            sockaddr_in bind_addr{};
            bind_addr.sin_family = AF_INET;
            bind_addr.sin_port   = htons(tc8::dut::kSdPort);
            bind_addr.sin_addr.s_addr = tester_ip;
            if (::bind(sock, reinterpret_cast<const sockaddr*>(&bind_addr),
                       sizeof(bind_addr)) < 0) {
                ::close(sock);
                return;
            }

            sockaddr_in dst{};
            dst.sin_family = AF_INET;
            dst.sin_port   = htons(tc8::dut::kSdPort);
            dst.sin_addr.s_addr = dut_ip;

            constexpr int kBurst = 100000;
            for (int i = 0; i < kBurst; ++i) {
                ssize_t n = 0;
                while (true) {
                    n = ::sendto(sock, datagram.data(), datagram.size(), 0,
                                 reinterpret_cast<const sockaddr*>(&dst),
                                 sizeof(dst));
                    if (n >= 0) break;
                    if (errno == ENOBUFS || errno == EAGAIN) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(2));
                        continue;
                    }
                    break;  // hard error — give up this iter
                }
                std::this_thread::sleep_for(std::chrono::microseconds(1500));
            }
            ::close(sock);
        }).detach();
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts152SM, someip_ets_152)
