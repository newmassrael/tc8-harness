#pragma once

#include <cstdint>
#include <vector>

#include "sce_integration/dut_socket_control.h"

// Service-primitive pass-through of the Tier-2 DUT-control seam: the untyped
// complement of the typed sub-interfaces (ITcpControl, IArpControl, ...).
//
// A typed sub-interface names an operation the harness understands, so a case speaks
// the operation and the backend maps it to its wire. A DUT can also serve primitives
// of its own, whose group and primitive numbers and parameter layouts belong to the
// party that owns the DUT and which this repository must not know. They have no typed
// seam and never will; what they need is the harness's own accounting, applied to a
// call whose meaning only the caller knows.
//
// So the sub-interface carries a primitive by number and passes the bytes through,
// and the decorator (RecordingDutControl) accounts for it like any other DUT-control
// action. The meaning stays with the caller, in two places:
//   - what the reply says: the reply carries the result id and the parameter bytes
//     untouched, and the caller decodes them;
//   - why the call was made: a stimulus the case relies on, an answer it grades, or
//     cleanup (DutCallIntent, dut_call_intent.h). A state read is an observation
//     whatever the DUT answers, so a case that asks one wraps the call in
//     DutCallIntentScope(kGraded); the default intent, kStimulus, treats an answer
//     other than success as a stimulus that did not take.
//
// The record the decorator makes for a call that did not take names the operation, not
// the primitive: the numbers are the DUT owner's, and a report is read by people the
// numbers may not be shared with.

namespace tc8::sce {

// What a service-primitive call got back. Three outcomes, as DutCallOutcome has them:
// the DUT answered success; it answered that it would not (a result id other than
// success); or nothing usable came back, which says nothing about the DUT.
struct DutPrimitiveReply {
    DutCallOutcome::Kind kind = DutCallOutcome::Kind::kNoAnswer;
    // Why the DUT refused, in the seam's backend-neutral terms (the same classification a
    // socket option's refusal carries: a primitive the DUT does not serve is kUnsupported).
    DutCallOutcome::Refusal refusal = DutCallOutcome::Refusal::kNone;
    std::uint8_t result_id = 0;      // the DUT's result id, when it answered
    std::vector<std::uint8_t> data;  // the parameter data of the answer, when it answered

    bool answered() const { return kind != DutCallOutcome::Kind::kNoAnswer; }
    bool succeeded() const { return kind == DutCallOutcome::Kind::kDone; }

    // The outcome in the shape the decorator accounts.
    DutCallOutcome outcome() const { return DutCallOutcome{kind, refusal}; }
};

class IServicePrimitiveControl {
public:
    virtual ~IServicePrimitiveControl() = default;

    // Call primitive `pid` of group `gid` with parameter bytes `dat`, and wait for the
    // DUT's answer.
    virtual DutPrimitiveReply call(std::uint8_t gid, std::uint8_t pid,
                                   const std::vector<std::uint8_t> &dat) = 0;
};

}  // namespace tc8::sce
