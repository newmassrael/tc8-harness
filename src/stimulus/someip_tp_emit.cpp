#include "stimulus/someip_tp_emit.h"

#include <optional>
#include <vector>

#include "stimulus/tx_observer.h"
#include "stimulus/udp_emit.h"

namespace tc8::stimulus {

int emitSomeIpTpSegments(std::string_view iface, std::uint16_t src_port,
                         const someiptp::MessageHeader &hdr, const std::uint8_t *payload,
                         std::size_t len, std::uint32_t dst_ip_be, std::uint16_t dst_port,
                         std::size_t max_segment_payload, std::uint8_t reserved,
                         const std::vector<int> &segment_steps) {
    TC8_TX_SCOPE();
    const someiptp::Segmenter segmenter(max_segment_payload);
    const std::vector<std::vector<std::uint8_t>> segments =
        segmenter.segment(hdr, payload, len, reserved);
    for (std::size_t k = 0; k < segments.size(); ++k) {
        // No scope for a segment the list does not name, so the caller's step stays.
        std::optional<TxSpecStep> step;
        if (k < segment_steps.size()) {
            step.emplace(segment_steps[k]);
        }
        const int rc = sendUdpUnicast(segments[k], iface, src_port, dst_ip_be, dst_port);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

}  // namespace tc8::stimulus
