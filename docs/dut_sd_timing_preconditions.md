# Per-Case DUT SD-Timing Preconditions

This document is the **single source of truth** for the harness mechanism that lets a
conformance case run under the DUT SOME/IP-SD start-up timer configuration that *its
precondition* specifies, rather than under the one global config the DUT is otherwise
brought up with.

## The problem

The DUT is started with exactly one vsomeip config per invocation
(`VSOMEIP_CONFIGURATION` → `dut/dut_service/vsomeip.json`, or a deployment-derived
copy). Some Service-Discovery start-up cases, however, each declare a *different*
`service-discovery` timer value as a precondition. A single global config cannot honour
a set of mutually-incompatible per-case preconditions at once.

The public OPEN Alliance TC8 §5.1.5.4 `SOMEIPSRV_SD_BEHAVIOR` cases the harness ships
do **not** need this — their prerequisites are `N/a` or `CYCLIC_OFFER_DELAY > 0`, both
satisfied by the reference `vsomeip.json`. The mechanism exists for **deployments whose
profile adds per-case timer preconditions**; it keeps such a deployment from having to
either edit the shared harness or compromise on a single global config.

## The mechanism

A `--topology-conf` overlay declares, per case, the `service-discovery` field values
that case needs. When the runner brings the DUT up for that case it derives a per-worker
vsomeip config = **the resolved base config PATCHED with those fields**, and points the
DUT at it.

Because it *patches the active base* (composition) rather than swapping to a fixed
file, it composes with whatever base the run resolved: the reference `vsomeip.json`, a
`services[]` variant (`vsomeip-multi-*.json`), or a deployment-derived config — nothing
else the base declared (services, events, eventgroups) is lost. This is the same
derive-don't-copy principle as the base identity-surface generators: no hand-maintained
per-precondition config file that could silently drift from the base.

### Declaring the overrides (overlay)

The overlay (which `smoke-test.sh` *sources*) adds entries to the associative array
`TC8_TOPOLOGY_DUT_SD_TIMING`, keyed by the **display case id** — the exact form
`tc8-harness test --list-cases` prints: a bare id **upper-cased**, or a qualified
`suite:id` (non-default suite) with the suite prefix **verbatim** and only the local id
upper-cased (e.g. `vendorx:SOMEIPSRV_SD_BEHAVIOR_02`). The runtime derives the same form via
`canonicalise_case_id`, so validate and the per-case lookup agree. The value is a
space-separated `KEY=VALUE` list of `service-discovery` field overrides — for example:

```bash
# in your --topology-conf overlay: a case that needs a specific SD start-up timer
TC8_TOPOLOGY_DUT_SD_TIMING[MY_SD_TIMING_CASE]="initial_delay_min=<ms> initial_delay_max=<ms>"
```

The array is declared empty by `smoke-test.sh`, so a run with no overlay — or an
overlay that never sets it — uses the base config unchanged, byte-identical to today.

`KEY` may be any field the base config's `service-discovery` block already declares (the
overridable set is *derived from the base*, not a list the harness hard-codes — so it
stays in step with whatever timers the deployment's config actually has). `VALUE` is a
non-negative integer, so the block's string fields (`enable`, `multicast`, `protocol`)
cannot be set this way; the intended targets are the start-up timers
(`initial_delay_min`/`max`, `repetitions_base_delay`, `repetitions_max`,
`cyclic_offer_delay`, `ttl`), though any integer-valued field the base declares (e.g.
the SD `port`) is reachable — the map is deployment-owned config, not a silent
capability. A KEY the base does not declare, a non-integer VALUE, or a base with no
`service-discovery` block is a **fail-loud** error (a precondition typo must not
silently no-op).

### Fail-fast validation at overlay load

Before any worker runs, `validate_dut_sd_timing_overrides` (in `smoke-test.sh`, right
after the overlay is sourced) checks every declared entry and **aborts the whole run**
with a clear message if:

- the entry is keyed on a case id the harness registry does not know
  (`tc8-harness test --list-cases`) — a typo that would otherwise never match a running
  case and let it run under the *unpatched* config, silently defeating the precondition;
- any override token is malformed (checked against the base via the transform's own
  `--validate`, a dry-run of the exact apply the runtime performs).

So a deployment-config error surfaces immediately as a config error, never later as a
per-case conformance FAIL and never as a silent no-op.

## Scope: bash smoke-test only

This is a `dut/env/smoke-test.sh` feature, exactly like the existing
`CASE_VSOMEIP_VARIANT` (services[] variant) selection. The Rust `tc8-orchestrator`
brings the DUT up with one config for the run and has no per-case DUT-config axis at
all, so there is nothing to mirror there and no cross-driver drift to gate — the
override is DUT configuration, not part of the `--expect` identity surface the two
drivers keep in parity.

## Implementation

- `tools/dut_sd_timing_override.py` — the pure transform (patch a base's
  `service-discovery` fields; derive the overridable set from the base; fail loud on a
  bad token). `--validate` is a dry-run apply used by the load-time check; `--self-test`
  is an inline unit test wired into CI (build-test.yml) — it exercises the transform's
  composition/validation guarantees, not a cross-file drift gate.
- `dut/env/smoke-test.sh` — `validate_dut_sd_timing_overrides` (load-time fail-fast) and
  `resolve_dut_sd_timing_cfg` (per-case runtime apply, on both the positive `run_case`
  and negative `run_negative_case` DUT bring-up paths). Derived per-worker configs live
  under the per-worker scratch (`$WORK_ROOT/$W`), cleaned at teardown.

## Relationship to the expect surface (verdict side)

A timing verdict compares a captured delay against an *expected window*, which a case
supplies through the `--expect` surface (e.g. `sd_initial_delay_min_ms`,
`sd_initial_delay_max_ms`, and `sd_service_down_ms`; see
`src/sce_integration/someip_expectations.h`). The DUT-config precondition here and the
expected-window value there are two ends of the same fact: a deployment is expected to
single-source them on its side (declare the timer once, feed both the
`TC8_TOPOLOGY_DUT_SD_TIMING` override that provisions the DUT and the matching
`--expect` token the verdict reads). The harness deliberately keeps the two channels
separate — the expected window is not always equal to the configured timer (tolerance,
raw-startup residual) — so their coupling stays a deployment decision, not a hard-wired
harness identity.
