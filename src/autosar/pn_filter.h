#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tc8::pn {

// Where the Partial Networking Cluster (PNC) bit vector lives inside an NM PDU.
// Both fields are OEM configuration: the offset and width of the PN range are
// fixed by the OEM's NM PDU layout, never by this repository.
struct PnConfig {
    std::size_t pni_offset;  // byte offset of the PNC bit vector within the PDU
    std::size_t pni_len;     // width of the PNC bit vector, in bytes (> 0)
};

// AUTOSAR Partial Networking relevance filter (AUTOSAR Partial Networking, as
// used by UdpNm/CanNm). An NM PDU carries a PNC bit vector — one bit per
// Partial Network Cluster — at PnConfig{pni_offset, pni_len}. A receiving ECU
// must wake / stay awake for the PDU only when it requests at least one cluster
// the ECU participates in.
//
// The *mechanism* is the only thing here and it is vendor-neutral: relevance is
// a bitwise AND of the received PN range with the ECU's own cluster mask, tested
// for any surviving bit. Everything proprietary is a parameter — the range
// location (PnConfig), and which clusters the ECU belongs to (the per-call
// `my_clusters` mask). The PNC-ID-to-bit assignment never appears here; the OEM
// expresses it by which bits it sets in `my_clusters`, in the same byte/bit
// layout as the on-wire PN range.
class PnFilter {
public:
    // pni_len must be non-zero (a zero-width PN range is a configuration error).
    explicit PnFilter(PnConfig config);

    // True iff the PNC bit vector in `nm_pdu` shares a set bit with
    // `my_clusters` — i.e. the PDU requests a cluster this ECU participates in.
    //
    // `my_clusters` is the ECU's PNC membership mask and must be exactly
    // pni_len bytes (the PNC bit space is fixed-width); any other size throws
    // std::invalid_argument. If the PDU is too short to contain the configured
    // PN range the range is absent, so the result is false (no cluster can be
    // requested) rather than an error — a short PDU is runtime data, not
    // misconfiguration.
    bool relevant(const std::uint8_t* nm_pdu, std::size_t len,
                  const std::vector<std::uint8_t>& my_clusters) const;

private:
    PnConfig config_;
};

}  // namespace tc8::pn
