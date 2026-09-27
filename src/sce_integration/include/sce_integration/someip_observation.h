#pragma once

#include <cstdint>
#include <variant>

#include "tc8/captured_event.h"

#include "someip_captured.h"
#include "stimulus_observation.h"

namespace tc8::sce {

// Observation predicates over SOME/IP-SD traffic, for a stimulus that awaits the
// DUT's SD behaviour (stimulus_observation.h).
//
// Each one decodes through `fillSomeIpCapturedFromFrame` — the decoder the case's
// own SCXML guards read — so a stimulus and the verdict it prepares cannot
// disagree about what a given SD message is. A predicate here that re-parsed the
// SD payload itself would be a second decoder, and the first place the two drift
// is exactly the frame a case waits on.

// An SD message FROM the DUT whose first entry is of `entry_type` for
// `service_id` — the shape an SCXML `sd_entries[0]` guard grades.
//
// The source is part of the predicate, unlike most SCXML guards, because a
// stimulus emits SD itself: the tester's own FindService is on the same capture,
// and a wait it could satisfy would release the next step on the tester's frame
// instead of the DUT's. `dut_ip_be` is `TestConfig::dut.ip` (network byte order,
// the same encoding the capture uses); 0 — no DUT address known — matches
// nothing, so the wait is reported unmet rather than satisfied by an unknown
// sender.
inline ObservationPredicate dutSdFirstEntry(std::uint32_t dut_ip_be, std::uint8_t entry_type,
                                            std::uint16_t service_id) {
    return [dut_ip_be, entry_type, service_id](const ::tc8::CapturedEvent &ev) {
        const auto *f = std::get_if<::tc8::SomeIpFrame>(&ev);
        if (f == nullptr || dut_ip_be == 0U || f->src_ip != dut_ip_be) {
            return false;
        }
        SomeIpCaptured c{};
        fillSomeIpCapturedFromFrame(c, *f);
        return c.headerIsSd() && c.sd_entry_count >= 1 && c.sd_entries[0].type == entry_type &&
               c.sd_entries[0].service_id == service_id;
    };
}

}  // namespace tc8::sce
