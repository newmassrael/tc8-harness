# Per-case `--expect` overrides — rationale

`docs/spec/inventory_overrides.json` carries the **values** of the
`expect_overrides` axis; this file carries **why** each one exists, and is the
home of their spec-section citations.

The split follows the overrides file's own convention: a value there names its
prose here through a `*_ref` field, exactly as `platform_known_fail_ref` points
at a memory note. It is also required — `mnemosyne.toml`'s `[workspace]` records
that `docs/spec/*` (the TC8 PDFs and the mined JSON) is immutable legacy outside
Mnemosyne's managed surface, so a `§` citation placed there would carry no
binding. `dut/` is a scan root, so the citations below stay bound.

## Why the axis exists

Every case is invoked with the same **deployment identity** `--expect` surface —
the DUT's service/instance/major/ports/MAC/IPs, derived from `vsomeip.json` and
single-sourced across the drivers by `tools/expect_surface.def` (see
docs/tech-debt.md TD-12). That surface describes the DUT, and it is identical for
all 543 cases.

A handful of cases need one comparison target that the deployment does **not**
determine, because their own **stimulus** chose it. The overwhelming case is the
subscribed eventgroup: the trait subscribes to a specific eventgroup, and the
SCXML guard then asserts `captured.eventgroup_id == expected.eventgroup_id`. The
expected value must therefore follow the *stimulus*, not the deployment. That
makes it a property of the case — the same kind of fact as `timing_serial` or
`platform_known_fail`, and it lives in the same place for the same reason.

The eventgroups themselves are declared under `TestEventUINT8` in
`dut/ets/ets.fdepl` and the matching blocks in `dut/dut_service/vsomeip.json`.
The base identity carries eventgroup 0x0001, so the other §5.1 cases — whose
stimulus subscribes to that default, or whose verdict never reads
`expected.eventgroup_id` at all — need no entry here. Only a case that diverges
appears below; an override is evidence that the case's stimulus made a choice,
not a knob to be set casually.

`TestCommand::runCase` appends these tokens **after** the driver's, and each
`applyExpectToken` assigns its field, so the case value simply wins. There is no
merge logic and no precedence table. Drivers emit only the base identity and
never read this axis, which is what makes bash and the orchestrator structurally
unable to drift on it.

## The cases

### SOMEIPSRV_BASIC_03 — eventgroup 0x0002

The reference case for the Subscribe → Ack → Notification chain. Its trait
subscribes to eventgroup 0x0002, and the verdict asserts the Notification's
identity against `expected.eventgroup_id`. Several cases below are described
relative to this one.

### §5.1.5.1.28 SOMEIPSRV_FORMAT_28 — eventgroup 0x0002

FORMAT_28 round-trip `eventgroup_id` check: the trait subscribes to eg 0x0002
(Ack path); the SCXML cond checks `captured.eventgroup_id ==
expected.eventgroup_id`, so the `--expect` must match the trait's subscribe
target.

Sister cases FORMAT_19..27 do **not** read `expected.eventgroup_id` — they assert
Type/Length/IndexFirst/Service/Instance/Major/TTL/Reserved against the configured
identity, which is unchanged — so they need no per-case override even though
their stimulus also subscribes to 0x0002 for the Ack path.

### §5.1.5.3 SOMEIPSRV_SD_MESSAGE_09 — eventgroup 0x0002

Same eventgroup target as BASIC_03; the verdict differs (Notification UDP
`src_port` vs OfferService Endpoint Option port) but the stimulus and the
Subscribe target are identical.

### §5.1.5.5 SOMEIPSRV_OPTIONS_08..14 + §5.1.5.3 SOMEIPSRV_SD_MESSAGE_13 — eventgroup 0x0008

Cases: SOMEIPSRV_OPTIONS_08, SOMEIPSRV_OPTIONS_09, SOMEIPSRV_OPTIONS_10,
SOMEIPSRV_OPTIONS_11, SOMEIPSRV_OPTIONS_12, SOMEIPSRV_OPTIONS_13,
SOMEIPSRV_OPTIONS_14, SOMEIPSRV_SD_MESSAGE_13.

These subscribe to the multicast-configured eventgroup 0x0008 (declared under
`TestEventUINT8` in `dut/ets/ets.fdepl` plus the matching multicast block in
`vsomeip.json`). The override keeps the SCXML `eventgroup_id` assertions
consistent with the stimulus.

### §5.1.6 SOMEIP_ETS_086 (0x0002) / SOMEIP_ETS_087 (0x0005)

These lift BASIC_03's Subscribe → Ack → Notification chain onto eventgroups 0x02
and 0x05 respectively. The same per-case `eventgroup_id` override pattern keeps
the SCXML phase-2 assertion consistent with the stimulus.

### §5.1.6 SOMEIP_ETS_121 — eventgroup 0x0005

Mirrors _087 — the Subscribe(eg 0x05) phase-2 cond uses
`expected.eventgroup_id`.

### §5.1.6 SOMEIP_ETS_094 — eventgroup 0x0002

Subscribes to eg 0x02; the server-side reboot-detection chain reuses the
BASIC_03 wire shape.

### §5.1.6 SOMEIP_ETS_154 — eventgroup 0x0002

The stimulus targets the configured eg 0x02 so the option walker reaches the IPv4
endpoint validation step — subscribing to an unknown eventgroup would
silent-drop earlier.

### §5.1.6 SOMEIP_ETS_162 / SOMEIP_ETS_163 — eventgroup 0x0002

Mirror ETS_154: the configured eg 0x02 keeps the option walker reaching the IPv4
validation step before the silent-drop.

### §5.1.6 SOMEIP_ETS_109 / _110 / _111 / _112 / _113 / _119 — eventgroup 0x0002

Cases: SOMEIP_ETS_109, SOMEIP_ETS_110, SOMEIP_ETS_111, SOMEIP_ETS_112,
SOMEIP_ETS_113, SOMEIP_ETS_119.

Mirror ETS_134: the configured eg 0x02 keeps the option walker active so each
malformation axis is exercised before the silent-drop gate.

### §5.1.6 SOMEIP_ETS_115 / _116 / _174 / _178 — eventgroup 0x0002

Cases: SOMEIP_ETS_115, SOMEIP_ETS_116, SOMEIP_ETS_174, SOMEIP_ETS_178.

Mirror ETS_134: the configured eg 0x02 keeps the option walker active for the
relevant axis.

### §5.1.6 SOMEIP_ETS_176 / SOMEIP_ETS_177 — eventgroup 0x0002

The stimulus runs on the configured eg 0x02 so the SubscribeAck observation
matches the `eventgroup_id` assertion.

### §5.1.6 SOMEIP_ETS_117 (0x0005) / SOMEIP_ETS_173 (0x0002) / SOMEIP_ETS_175 (0x0002)

These also subscribe on a configured eventgroup so the verdicts assert against
the same `eventgroup_id`. ETS_117 uses eg 0x05; _173 and _175 use eg 0x02.

### §5.1.6 SOMEIP_ETS_107 / SOMEIP_ETS_108 — eventgroup 0x0005

Subscribe on the configured eg 0x05.

### §5.1.6 SOMEIP_ETS_120 — eventgroup 0x0002

Subscribes to the configured eg 0x02.

### §5.1.6 SOMEIP_ETS_155 — eventgroup 0x0002

Chains Subscribe / Stop / Subscribe on the configured eg 0x02 so both Acks land
on the `eventgroup_id` cond.

### §5.1.6 SOMEIP_ETS_152 — eventgroup 0x0002

Burst Subscribes target the configured eg 0x02 so each emit elicits an Ack and
bumps vsomeip's outgoing SD `session_id` counter — every Ack contributes to the
wrap timeline.

### §5.1.6 SOMEIP_ETS_147 — eventgroup 0x0002

Subscribes to eg 0x02 (mirror of _086).

### §5.1.6 SOMEIP_ETS_148 / SOMEIP_ETS_149 — eventgroup 0x0002

Also subscribe to eg 0x02.

### §5.1.6 SOMEIP_ETS_151 — eventgroup 0x0002

Subscribes to eg 0x0002 (mixed; carries reliable 0x8003 per `ets.fdepl`) over a
live TCP session.

### §5.1.6 SOMEIP_ETS_150 — eventgroup 0x0006

Subscribes to eg 0x06 (Multicast variant).
