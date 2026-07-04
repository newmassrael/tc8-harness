# SD Start-Marker Testability Profile

This document is the **single source of truth** for the SOME/IP-SD *start-marker*
testability profile: the wire contract that lets the harness measure a DUT's
Initial-Wait delay — the randomized wait before a server emits its first multicast
`OfferService` — **soundly**, on any DUT that implements the profile, not only the
reference vsomeip stack.

The harness half of the contract is live: the reserved marker id
(`src/someip/protocol.h`), the recognizer and anchor
(`tc8::SomeIpCaptured::is_sd_start_marker` / `sd_start_ts_us` /
`delta_from_sd_start_us` in `src/sce_integration/someip_captured.h`), and the trace
emit (`decode_pcap` exporter) are all in-tree. The DUT half is an opt-in,
default-off reference implementation described in Section 5.

Verdict semantics referenced below are governed by `docs/verdict_policy.md`; this
page only adds the *measurement* contract, never a new verdict class.

---

## 1. What it measures

A conformant SOME/IP-SD server does not answer its first request immediately after
start-up. It observes the **Initial Wait Phase**: a delay drawn uniformly from a
configured `[min, max]` window before the first multicast `OfferService`. The
timing profile asserts that the first post-start `OfferService` lands inside that
window, and (for multi-restart cases) that independent restarts draw *different*
delays.

The quantity under test is therefore:

> `first OfferService egress` − `start() of the Initial-Wait timer`

both observed on the **same pcap clock**.

---

## 2. Why an internal anchor (the confound this profile removes)

The naive anchor is an *external* event the tester itself drives — the moment it
re-activates the DUT (`delta_from_listen_window_us`). That anchor is unsound for
this measurement: a warm restart runs hundreds of milliseconds of re-registration
between the external re-activation and the internal `start()` of the Initial-Wait
timer, and that re-registration time is **not** part of the Initial-Wait delay.
Anchoring externally folds restart jitter into the measured value:

- the single-restart window check inherits a large, DUT-load-dependent offset, and
- the multi-restart "delays must differ" check can pass on restart jitter alone,
  i.e. a **false pass**.

The profile replaces the external anchor with an internal one the DUT itself emits
at the exact instant the Initial-Wait timer is armed, so the subtraction brackets
only the `start() -> Offer` gap. Because both stamps are pcap arrival times, the
measurement stays valid even when the DUT and the tester run on different hosts.

---

## 3. The wire contract (vendor-facing)

A DUT that implements the profile emits **exactly one `OfferService` entry for the
reserved marker service id** to the SD multicast group, from the point in its SD
start-up where the Initial-Wait timer is armed:

| field | value | note |
|-------|-------|------|
| SD Message ID | service `0xFFFF` / method `0x8100` | normal SD channel |
| entry type | `OfferService` (`0x01`) | an entry is present — no special send path |
| service id | **`0xFFFD`** (`kSdStartMarkerServiceId`) | reserved; no real service uses it |
| instance id | `0x0001` | |
| major / minor | `0x01` / `0x00000000` | |
| TTL | small, non-zero | a live Offer, not a StopOffer |

Recognition is by **presence** of the reserved service id — a positive,
self-identifying signature — never by absence of entries. Two consequences follow:

- A stray, other-stack, or parse-failed SD frame between the real marker and the
  measured Offer can **never** be mistaken for the anchor, so it cannot pull a
  too-slow (non-conformant) Offer into range.
- The DUT must **not** register a real `serviceinfo` for `0xFFFD`; it hand-builds
  the single entry so nothing else in the stack treats the marker id as an offered
  service.

The marker is emitted only while the profile is enabled (Section 5) — a normal
run never carries it.

### Reserved-id allocation

`0xFFFD` is dedicated to the marker and is deliberately distinct from `0xFFFE`, the
unknown-service sentinel (`sd_test_unknown::kServiceId`) used by the negative-axis
"unknown service" cases, so the marker and those cases never collide. Both literals
are single-sourced in `src/someip/protocol.h`.

---

## 4. Harness side (how the tester anchors)

Live in `src/sce_integration/someip_captured.h` on `tc8::SomeIpCaptured`:

- `is_sd_start_marker()` returns true for an `OfferService` whose first entry
  advertises `someip::kSdStartMarkerServiceId`. It delegates to the shared
  `is_offer_service_for(...)` proof-of-life predicate, so the marker recognizer
  cannot drift from the ordinary OfferService recognizer.
- `fillSomeIpCapturedFromFrame` stamps `sd_start_ts_us` from the marker frame's
  pcap arrival time (`observed_ts_us`, `CLOCK_REALTIME`). The stamp is **only set,
  never cleared**, so it persists across later frames to the first post-start real
  Offer. For an N-restart case each restart emits its own marker, overwriting the
  previous stamp, so every measured Offer anchors on its own `start()`.
- `delta_from_sd_start_us()` returns `positiveGapFrom(sd_start_ts_us)` — the
  microsecond gap from the marker to the current frame, sharing the base timing
  guard: it returns `0` when no marker was seen, and clamps a negative raw
  difference to `0`.
- The `decode_pcap` trace emits `delta_from_sd_start_us` only when a marker was
  seen (`sd_start_ts_us != 0`), so golden traces of non-timing runs are unchanged.

---

## 5. Reference DUT implementation (vsomeip)

The reference stack satisfies the contract behind a compile guard,
`ENABLE_SD_START_MARKER`, **default off → byte-identical to stock**. When the guard
is defined, an ETS method (`setSdStartMarker(bool)`, default off) arms the marker
for the duration of one timing measurement; no other case ever observes it.

- The marker is emitted from `service_discovery_impl::start()`, immediately before
  the Initial-Wait timer is armed (`start_offer_debounce_timer(true)`).
- It is built as one hand-rolled `OfferService` entry for the marker id and sent
  through the ordinary multicast SD send path (an Offer has an entry, so no
  entry-less special case is needed).
- The reference constant `VSOMEIP_SD_START_MARKER_SERVICE` **must equal** the
  harness `someip::kSdStartMarkerServiceId` (`0xFFFD`). The two are a documented,
  hand-kept pair — the harness value is authoritative.

The enable plumbing (application → routing manager → service discovery) mirrors the
existing per-case tuning method used for request/response delay; it carries a single
`bool` instead of the delay's parameters.

---

## 6. Faithfulness and caveats

The profile is a testability aid, not a pure passive probe. Two effects are
inherent and must be named wherever it is used:

- **Session-id side effect.** Sending the marker stamps and increments the DUT's SD
  session counter, so the first real Offer's session id is shifted by one while the
  marker is enabled. This is harmless for the isolated, default-off timing case and
  for strict SD-session-increment assertions, but it means the marker is not
  side-effect-free. It is only ever enabled during a timing measurement.
- **Measurement bias.** The marker egresses via the same send path as the Offer, so
  the per-side egress cost is approximately equal and the residual bias is one I/O
  flush on each side — sub-millisecond against a window measured in tens of
  milliseconds.

---

## 7. Measurement and verdict semantics

A timing case compares `delta_from_sd_start_us()` against the configured window,
with a tolerance so that a delay drawn near a boundary plus sub-millisecond jitter
cannot false-fail:

```
delta_from_sd_start_us() >= (initial_delay_min_ms - timing_tolerance_ms) * 1000
&& delta_from_sd_start_us() <= (initial_delay_max_ms + timing_tolerance_ms) * 1000
```

- **Single restart** — the first real Offer's delta must fall in the window.
- **Multiple restarts** — each restart's delta is recorded and the deltas must
  differ (by more than the tolerance). This is sound with the internal anchor:
  restart jitter is excluded, so the spread is the randomized Initial-Wait pick and
  nothing else.
- **Fail-closed.** If the marker never arrives — the profile is disabled, or the DUT
  does not implement it — `delta_from_sd_start_us()` returns `0`, the lower-bound
  guard fails, and the case is **inconclusive**, never a false pass. Per
  `docs/verdict_policy.md`, a testability shortfall is a property of the test set-up
  (`inconclusive`), not an observed DUT violation (`fail`).

---

## 8. Constants (SSOT)

| constant | value | home |
|----------|-------|------|
| `someip::kSdStartMarkerServiceId` | `0xFFFD` | `src/someip/protocol.h` |
| `sd_test_unknown::kServiceId` (contrast) | `0xFFFE` | `src/someip/protocol.h` |
| SD Message ID (service / method) | `0xFFFF` / `0x8100` | `src/someip/protocol.h` |
| `VSOMEIP_SD_START_MARKER_SERVICE` (reference DUT) | must equal `0xFFFD` | reference vsomeip patch |

The harness constant is authoritative. Any DUT that implements the profile — and the
reference vsomeip constant — must track it.
