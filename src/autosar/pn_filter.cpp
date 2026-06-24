#include "autosar/pn_filter.h"

#include <stdexcept>

namespace tc8::pn {

PnFilter::PnFilter(PnConfig config) : config_(config) {
    if (config_.pni_len == 0) {
        throw std::invalid_argument("tc8::pn::PnFilter: pni_len must be non-zero");
    }
}

bool PnFilter::relevant(const std::uint8_t* nm_pdu, std::size_t len,
                        const std::vector<std::uint8_t>& my_clusters) const {
    if (my_clusters.size() != config_.pni_len) {
        throw std::invalid_argument(
            "tc8::pn::PnFilter::relevant: my_clusters must be pni_len bytes");
    }
    // The PN range must lie wholly within the PDU; otherwise it is absent and no
    // cluster is requested. The bounds add avoids overflow on a hostile offset.
    if (config_.pni_offset > len || config_.pni_len > len - config_.pni_offset) {
        return false;
    }
    for (std::size_t i = 0; i < config_.pni_len; ++i) {
        if ((nm_pdu[config_.pni_offset + i] & my_clusters[i]) != 0) {
            return true;
        }
    }
    return false;
}

}  // namespace tc8::pn
