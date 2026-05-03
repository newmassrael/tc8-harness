#include "cli/capture_driver.h"

#include <cstdint>
#include <cstdio>
#include <variant>

#include <pcap/pcap.h>

#include "tc8/captured_event.h"

#include "capture/pcap_source.h"
#include "cli/signal_handler.h"
#include "dissect/packet_pipeline.h"
#include "dissect/someip_header.h"

namespace tc8::cli {

namespace {

void printCaptured(const ::tc8::CapturedEvent &ev) {
    std::visit(
        [](const auto &f) {
            using T = std::decay_t<decltype(f)>;
            if constexpr (std::is_same_v<T, ::tc8::SomeIpFrame>) {
                std::printf("[%s] svc=0x%04x mth=0x%04x len=%u sess=0x%04x type=0x%02x "
                            "rc=0x%02x payload=%u\n",
                            f.is_tcp ? "TCP" : "UDP", f.service_id, f.method_id, f.length, f.session_id, f.message_type,
                            f.return_code, f.payload_len);
            }
            // Other variants are emitted once their decoders land (§4.2 onward).
        },
        ev);
}

}  // namespace

int runCapture(std::unique_ptr<capture::PcapSource> src, const std::string &bpf) {
    src->applyBpf(bpf);
    SignalGuard guard(*src);

    const int dlt = src->datalink();
    std::printf("bpf      : %s\n", bpf.c_str());
    std::printf("datalink : %d (DLT)\n", dlt);

    dissect::PacketPipeline pipeline(printCaptured);
    pipeline.setTstampPrecision(src->tstampPrecision());

    std::uintmax_t frames = 0;
    std::uintmax_t bytes = 0;

    while (!SignalGuard::stopRequested()) {
        const int n = src->dispatch(
            /*max_frames=*/-1, [&](const pcap_pkthdr &hdr, const u_char *data) {
                ++frames;
                bytes += hdr.caplen;
                pipeline.processFrame(hdr, data, dlt);
            });
        if (n < 0) {
            if (n == -2) {
                break;  // pcap_breakloop — graceful shutdown
            }
            std::fprintf(stderr, "dispatch error: %s\n", src->lastError());
            return 1;
        }
        if (n == 0 && src->isOffline()) {
            break;  // end of pcap file
        }
    }

    std::printf("captured : %ju frames, %ju bytes\n", frames, bytes);
    return 0;
}

}  // namespace tc8::cli
