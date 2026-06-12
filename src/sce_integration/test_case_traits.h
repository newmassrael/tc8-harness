#pragma once

#include <string_view>
#include <type_traits>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "test_config.h"

namespace tc8::sce {

// Forward declaration — full definition in `test_runner.h`. Declared
// here so `has_scheduled_stimulus` (below) can refer to the type
// inside its SFINAE probe without pulling the runner include.
class IStimulusScheduler;

// Per-case metadata plugged into TestRunner<StateMachine> and
// CaseRegistry. The primary template is left undefined on purpose: an
// unspecialized instantiation must be a compile-time error, not a
// silent fall-through.
//
// Specializations must provide the following static members:
//
//   Identity / reporting (mirrored into CaseEntry):
//     static constexpr std::string_view kCaseId;       // "SOMEIPSRV_FORMAT_01"
//     static constexpr std::string_view kSpecSection;  // "5.1.5.1.1"
//     static constexpr std::string_view kDescription;  // Synopsis row
//     static constexpr bool             kDeprecated;   // Deprecated / Deleted Test Case
//     static constexpr int              kTopology;     // Test setup — Topology N
//     static constexpr ::tc8::BpfGroup  kBpfGroup;     // capture-filter bucket
//
//   Optional capture-filter override (out-of-tree escape hatch):
//     static constexpr std::string_view kBpfExpression;
//   A literal libpcap filter used VERBATIM instead of the
//   kBpfGroup-derived expression, for a case whose capture needs fall
//   outside the closed BpfGroup enum (e.g. an OEM protocol on a
//   non-standard port). Declared in the case's own header so an
//   out-of-tree case ships a novel filter without editing core
//   bpf_filter. Precedence: CLI `-f` > kBpfExpression > kBpfGroup. Like
//   `-f`, the string is passed to the kernel as-is, so the case owns its
//   own VLAN-awareness (see `vlanAware`). kBpfGroup stays required (it is
//   the reporting bucket) but is unused for the filter when this is set.
//
//   (Category is derived from kCaseId — everything before the final
//   "_<digits>" suffix — so there is no separate kCategory field. The
//   registrar static_asserts the required shape.)
//
//   Runtime plumbing for TestRunner<SM>:
//     using Captured = /* SCE Named Context struct dispatch() writes to */;
//     using Expected = /* SCE Named Context struct carrying CLI --expect */;
//     static void dispatch(Captured& captured,
//                          StateMachine& sm,
//                          const ::tc8::CapturedEvent& ev);
//     static std::string_view verdictFor(typename StateMachine::PolicyType::State);
//
//   Optional stimulus hook — receives the captured context by reference so
//   it can seed fields alongside the packet emit, the TestConfig so it can
//   forward CLI knobs like `--stimulus-wait`, and the egress interface name
//   threaded down from `--interface`:
//     static void stimulus(Captured& captured,
//                          const ::tc8::TestConfig& cfg,
//                          std::string_view iface);
//
//   Optional scheduled-stimulus hook (4-arg overload) — same as above
//   plus an `IStimulusScheduler&` the trait uses to enqueue
//   poll-loop-driven phase emits AFTER `kickStimulus` returns. Compound
//   shapes with an absence window followed by a positive phase opt
//   into this overload (e.g. §4.4.4.6 FRAGMENTS_02/03/04, §4.8.6.6
//   FLAGS_INVALID_01); the legacy 3-arg signature continues to work
//   for purely-synchronous stimulus. Cases that specialize BOTH
//   overloads will have the 4-arg one preferred — there is no
//   well-defined use for declaring both, so do not.
//     static void stimulus(Captured& captured,
//                          const ::tc8::TestConfig& cfg,
//                          std::string_view iface,
//                          ::tc8::sce::IStimulusScheduler& scheduler);
//
// `dispatch` is the single hand-off point from the capture pipeline. It
// inspects the variant, copies the relevant fields into `captured`, and
// raises the SCXML event(s) the case transitions on. Cases that only watch
// one protocol handle one alternative; cross-protocol cases (e.g. §4.2
// ARP_03 which observes both ARP and UDP in a single procedure) handle
// several. The expected-context handle is not passed to dispatch because
// wire events never mutate expected values — the SCXML guard compares
// `captured.*` against `expected.*` without dispatch involvement.
//
// Convention for event delivery inside `dispatch`:
//     sm.raiseExternal(Event::X);
//     sm.step();
// The `step()` synchronously processes the just-raised external event so
// the caller (`TestRunner::onCaptured`) sees the resulting transition
// before returning. Do NOT substitute `sm.tick()` here — `tick` pumps
// the scheduler in addition to processing the queue, and duplicating
// that with the per-tick pump in `TestRunner::tick()` would race
// scheduled-event delivery against wire-event delivery in the same
// macrostep, yielding non-deterministic ordering across cases.
// Scheduled events (`<send delay=.../>`) are handled by the idle path
// in `TestRunner::tick()`, not here.
//
// `stimulus` is the optional TESTER-side packet emit for cases whose
// TC8 Test Procedure begins with a tester-initiated request (e.g.
// FORMAT_12/13 start with a FindService so the DUT emits a solicited
// OfferService). The TestRunner detects the presence of this member via
// `has_stimulus` and calls it once after initialize() and after the
// capture pipeline has been opened — cases without a stimulus hook
// compile unchanged.
template <typename StateMachine> struct TestCaseTraits;

// Detects whether TestCaseTraits<SM> specializes a `static void stimulus(Captured&, ...)`
// hook. Kept here (not in TestRunner) so both the runner and unit tests
// can probe the same surface uniformly.
template <typename Traits, typename = void> struct has_stimulus : std::false_type {};

template <typename Traits>
struct has_stimulus<Traits, std::void_t<decltype(Traits::stimulus(std::declval<typename Traits::Captured &>(),
                                                                  std::declval<const ::tc8::TestConfig &>(),
                                                                  std::declval<std::string_view>()))>>
    : std::true_type {};

template <typename Traits> inline constexpr bool has_stimulus_v = has_stimulus<Traits>::value;

// Detects whether TestCaseTraits<SM> specializes the 4-arg
// `static void stimulus(Captured&, const TestConfig&, string_view,
// IStimulusScheduler&)` overload. TestRunner prefers the 4-arg form
// when both are defined; cases should pick exactly one signature.
template <typename Traits, typename = void>
struct has_scheduled_stimulus : std::false_type {};

template <typename Traits>
struct has_scheduled_stimulus<
    Traits,
    std::void_t<decltype(Traits::stimulus(
        std::declval<typename Traits::Captured &>(),
        std::declval<const ::tc8::TestConfig &>(),
        std::declval<std::string_view>(),
        std::declval<IStimulusScheduler &>()))>>
    : std::true_type {};

template <typename Traits>
inline constexpr bool has_scheduled_stimulus_v =
    has_scheduled_stimulus<Traits>::value;

// Detects whether TestCaseTraits<SM> specializes the 4-arg
// `static void dispatch(Captured&, StateMachine&, const CapturedEvent&,
// std::string_view iface)` overload. Cases whose dispatch helper needs
// the bound interface name to emit follow-up stimulus on every observed
// frame (e.g. §4.5.6.2 ADDRESS_SELECTION_14's self-loop conflict cycle)
// opt into the 4-arg form. The 3-arg signature continues to work for
// dispatch paths that don't emit anything during dispatch.
//
// TestRunner prefers the 4-arg form when both are defined; cases should
// pick exactly one signature.
template <typename Traits, typename = void>
struct has_iface_dispatch : std::false_type {};

template <typename Traits>
struct has_iface_dispatch<
    Traits,
    std::void_t<decltype(Traits::dispatch(
        std::declval<typename Traits::Captured &>(),
        std::declval<typename Traits::SM &>(),
        std::declval<const ::tc8::CapturedEvent &>(),
        std::declval<std::string_view>()))>>
    : std::true_type {};

template <typename Traits>
inline constexpr bool has_iface_dispatch_v =
    has_iface_dispatch<Traits>::value;

// Detects whether TestCaseTraits<SM> declares the optional
// `static constexpr std::string_view kBpfExpression` capture-filter
// override (see the contract above). `bpfExpressionOf<T>()` returns it
// when present and an empty view otherwise, so the registrar can carry
// it into CaseEntry uniformly — a case without the member compiles
// unchanged and falls back to its kBpfGroup-derived filter.
template <typename Traits, typename = void>
struct has_bpf_expression : std::false_type {};

template <typename Traits>
struct has_bpf_expression<Traits, std::void_t<decltype(Traits::kBpfExpression)>>
    : std::true_type {};

template <typename Traits>
inline constexpr bool has_bpf_expression_v = has_bpf_expression<Traits>::value;

template <typename Traits>
constexpr std::string_view bpfExpressionOf() {
    if constexpr (has_bpf_expression_v<Traits>) {
        return Traits::kBpfExpression;
    } else {
        return std::string_view{};
    }
}

}  // namespace tc8::sce
