# Tech-debt register

Known, accepted technical debt in tc8-harness. Each entry records WHAT the debt
is, WHY it exists, the RISK if left, the textbook FIX, and why it is DEFERRED.
This is a deliberate-deferral log, not a TODO list for unfinished features —
every item here is a working compromise with a documented escape path.

Entry format: a `## TD-NN` heading, then the fields below. Append new entries;
do not renumber. Reference an entry from code with a one-line pointer comment
(`see docs/tech-debt.md TD-NN`) at each coupled site so an editor of one site
discovers the others.

An entry whose **Status:** is OPEN must also carry a **Done when:** line naming
what would close it, in terms someone could check. An open debt with no closing
condition cannot be closed, only re-argued.

`tools/debt_census.py` reads this file and enforces that much. It also counts
the open work here together with the three other registers that hold some
(`tools/deferred_negatives.json`, `tools/negative_coverage_undisposed.txt`, and
`platform_known_fail` in the `inventory_overrides.json` files), because the
honest answer to "is there debt left?" is their union and no one file gives it.
An OPEN entry counts as repayable unless its id stands in
`tools/debt_accepted.txt` — the ratchet for debts argued to be immovable from
inside this repository. Put an id there only when the **Done when:** line names
something outside this repository's reach.

---

## TD-01 — SOME/IP-SD wire decode duplicated across C++ harness and Python site tooling

**Status:** RESOLVED (2026-06-29). **Logged:** 2026-06-29. Retained because the
in-code pointers (`see docs/tech-debt.md TD-01`) now resolve here for the
rationale behind the shared SSOT.

**What (the original debt).** The byte-level decode of SOME/IP-SD
entries/options was implemented independently in three places that had to agree
bit-for-bit:

- C++ — `src/sce_integration/someip_captured.h` (`decodeSdEntry`,
  `parseSdHeaderInto`, `parseSdOptionsInto`). Authoritative: drives conformance
  verdicts.
- Python — `site/scripts/decode_pcap.py` (decodes a captured pcap to JSON).
- Python — `site/scripts/generate_messages.py` (a cond evaluator that synthesises
  the same field names so the documentation site can resolve SCXML guard
  expressions over a decoded message).

There is no shared source for the wire layout (field offsets/widths); each side
hand-mirrors it.

**Why it exists.** The harness is C++ (it runs the live verdicts); the rendered
documentation site (`https://newmassrael.github.io/tc8-harness/`) is a separate
Python toolchain that decodes the captured pcaps to JSON for display. The two
share no runtime and no code, so the wire layout is mirrored by hand.

**Risk if left.** A wire-layout change must be applied by hand in all three
places. A miss is a SILENT divergence, not a build break: `site/` is not in the
harness CMake build or ctest, and the Python decoders have no cross-check against
the C++ struct. The harness verdict stays correct (C++ is authoritative), but the
site preview renders stale/UNKNOWN field values for the affected guards.

**Surfaced by.** The `reserved_counter` -> `entry_reserved` + `counter` SD-entry
split (commit `7e7422a5`). The initial change updated only the C++ decoder; a
3-agent cold review caught that both Python mirrors still emitted the removed
`reserved_counter` and lacked `entry_reserved`. All three were then migrated
together — this debt entry records the structural coupling that made the miss
possible.

**Resolution.** The SD wire layout is now written exactly once, in
`src/someip/someip_sd_wire.def` (X-macro form). Every fixed-offset SD
field — header, entry common fields, both entry-type tails (including the
bit-sliced `num_opt1/2` nibbles and the `Reserved(12b)|Counter(4b)` split that
surfaced this debt), and the IPv4 option tail — is one row carrying its
`(offset, size, shift, mask)`. Both languages derive from it:

- C++ (authoritative) `#include`s the `.def` directly in
  `someip_captured.h`, expanding each row into a read against the shared
  `tc8::sd_wire::readBe` primitive — the same X-macro idiom `verdict.h` uses for
  `verdict_taxonomy.def`. The C++ decoder is a direct consumer of the SSOT, not
  a generated artifact, so it cannot drift from it.
- Python `tools/gen_someip_sd_wire.py` parses the same `.def` and generates the
  site mirror `site/scripts/someip_sd_wire_generated.py`, imported by
  `decode_pcap.py`.

**Update (2026-07-01, TD-05).** The Python mirror is gone entirely. The site no
longer re-decodes the wire (TD-05): `decode_pcap.py`, the generator, and the
generated mirror were all deleted. `someip_sd_wire.def` remains the SSOT with a
single consumer — the C++ decoder (`someip_captured.h`) `#include`s it directly — so
there is no longer a cross-language pair to keep in step, and the `--check` freshness
gate was retired with the generator.

This also collapses the gratuitous field-name divergence: the Python mirror now
emits the canonical C++ names (`index_first`, `num_opt1`, ...), so
`generate_messages.py` no longer remaps entry names for the SCXML cond view.

Drift is now structural, not a review burden:

- A wrong offset/width is impossible to apply to only one language — the layout
  is in one file both consume.
- `python3 tools/gen_someip_sd_wire.py --check` (CI `build-test`, alongside the
  `gen_verdict_taxonomy`/`gen_wire_manifest` gates) fails if the committed
  Python mirror is stale w.r.t. the `.def`, and also runs a golden-vector
  self-test that catches a wrong number in the `.def` itself (a value both
  languages would otherwise mirror consistently-but-wrong).
- The existing C++ `someip_captured_test` suite (which exercises
  `decodeSdEntry`/`parseSdHeaderInto`/`parseSdOptionsInto`) pins the C++ side
  bit-for-bit; it passed unchanged across the refactor.

---

## TD-02 — DHCPv4 BOOTP wire decode duplicated across C++ pipeline and Python site

**Status:** RESOLVED (2026-06-30). **Logged:** 2026-06-29 (originally as "the
other TC8 protocols"; scope corrected 2026-06-30 — see "Premise correction").

**What (the original debt).** After TD-01 closed SOME/IP-SD, the DHCPv4 BOOTP
fixed header was still hand-decoded in two places that had to agree byte-for-byte:
`src/dissect/packet_pipeline.cpp` (C++, authoritative — drives §4.7 verdicts) and
`site/scripts/decode_pcap.py` (`_dissect_dhcpv4`, the documentation-site mirror).
The offsets (op/htype/hlen/hops/xid/secs/flags, the four IPv4 addresses, chaddr,
the magic cookie, the options start) were mirrored by hand, same shape as SD was.

**Premise correction (2026-06-30).** The original entry claimed every non-SD TC8
protocol carried this C++/Python decode mirror. Direct inspection narrowed it:
the C++ harness decodes the FIELDS of ARP / IPv4 / ICMPv4 / UDP / TCP through
libtins accessors (`ip->ttl()`, `tcp->seq()`, `arp->opcode()`, … in
`packet_pipeline.cpp`), not a hand-coded offset table — and the Python site
dissector hand-decodes the same fields, but as a single consumer a `.def` there
would not be an SSOT. So for FIELD DECODE, DHCPv4 (BOOTP, which libtins does not
dissect) is the lone genuine C++/Python offset mirror, and that part is fixed
here. The "other protocols' field decode" scope is WITHDRAWN as mis-scoped, not
deferred.

This premise is narrower than an earlier draft of it, which over-corrected to
"there are NO hand-coded byte offsets on the C++ side for those five." That is
false: the CHECKSUM validators still hand-code byte POSITIONS — `ipv4_captured.h`
`header_checksum_valid()` reconstructs the 20-byte IPv4 header from parsed fields,
and `packet_pipeline.cpp` extracts the TCP pseudo-header from IP bytes at offsets
12..19 — though the RFC 1071 FOLD itself now routes through the `tc8::wire` SSOT
(`inetChecksumValid`/`tcpChecksumValid`), not a hand-rolled sum. The IPv4 header
checksum is moreover independently implemented in `decode_pcap.py`
(`ip_header_checksum_ok`) — a real second cross-language duplication. It is an
ALGORITHM over RFC-frozen positions, not a field-layout table (the two sides even
differ in approach: C++ reconstructs-from-fields, Python sums raw bytes), so it
does not fold into the offset-`.def` mechanism; it is tracked separately as TD-04.

**Resolution.** The BOOTP fixed-header layout now lives once in
`src/sce_integration/dhcpv4_wire.def` (X-macro form). Both languages derive from
it: C++ (authoritative) `#include`s it via `src/sce_integration/dhcpv4_wire.h`
(`decodeBootpFixedHeader` / `magicCookieValid`, called from
`packet_pipeline.cpp`), and `tools/gen_dhcpv4_wire.py` generates the Python site
mirror `site/scripts/dhcpv4_wire_generated.py` imported by `decode_pcap.py`. The
shared big-endian read primitive was lifted out of the SD support header into
`src/wire/wire_read.h` (`::tc8::wire::readBe`) so both `.def` consumers
use one reader. Drift is now structural, same as TD-01:

- A wrong offset/width is impossible to apply to only one language.
- `python3 tools/gen_dhcpv4_wire.py --check` (CI `build-test`, alongside the
  `gen_someip_sd_wire`/`gen_wire_manifest` gates) fails on a stale mirror and runs
  a golden-vector self-test that catches a wrong number in the `.def` itself.
- `unit_tests/dhcpv4_wire_test.cpp` pins the C++ side bit-for-bit.

**Out of scope by design.** The post-cookie options TLV chain (code/length/value
walk: option 53 Message Type, Pad, END) has no fixed offsets, so it is decoded by
hand on each side and intentionally stays outside this offset SSOT; only the
options START offset is shared (`kOptionsOff`).

**Update (2026-07-01, TD-05).** The Python mirror is gone entirely (same as TD-01):
`decode_pcap.py`, `tools/gen_dhcpv4_wire.py`, and
`site/scripts/dhcpv4_wire_generated.py` were deleted when the site stopped
re-decoding the wire. `dhcpv4_wire.def` remains the SSOT with one consumer, the C++
decoder (`dhcpv4_wire.h`, used by `packet_pipeline.cpp`); the freshness gate was
retired with the generator. The hand-decoded options walk likewise now exists only
in C++.

## TD-03 — `--expect` key strings hand-duplicated across producers and the consumer

**Status:** RESOLVED (2026-06-30). **Logged:** 2026-06-30.

**What (the original debt).** Every `--expect` field name was a bare string literal
repeated across the producers that derive it from `vsomeip.json`
(`tools/dut_identity.py` and the orchestrator `dut/env/orchestrator/src/dispatch.rs`),
the bash emitter (`dut/env/smoke-test.sh`), and the C++ consumer
(`src/cli/expect_parser.cpp`). A key thus lived as an unshared literal in 4–5
places, and a rename in one was not a compile error in bash/Python.

**Risk (the original).** Partially gated: the orchestrator parity-check diffs the
bash vs Rust `--expect` dumps, and `config_test.rs` asserts the Python keys match
the Rust struct — so a producer-side typo was caught. The genuine gap was the
CONSUMER: nothing mechanically tied `expect_parser.cpp`'s key strings to a
registry, so a rename OR omission there silently dropped the field to its `0`
sentinel and the SCXML guard then compared against 0 (a false-pass, not a crash).

**Resolution.** The `--expect` schema is now written once, in
`src/cli/tc8_expect_keys.def` (X-macro form): one row per key carrying its group,
the group's namespace prefix, and its value kind (U8/U16/U24/U32/IPV4/MAC/payload).
The consumer is GENERATED from it — `expect_parser.cpp` expands the `.def` to build
each group's lookup table — so it accepts exactly the registry's key set and can
neither drift from nor omit a key (the property TD-01's wire decoder has). This
closes the CONSUMER-side false-pass: the original risk was a consumer key rename/
typo silently dropping a field, which is now impossible. Two further guards:

- Type safety: every key's setter dereferences the target member by its real type
  (key == member name), and `applyField<KIND>` `static_assert`s the kind's value
  class (IPv4→uint32, MAC→array<6>, numeric→matching width) against the member, so
  e.g. a U16 row on a uint32 member is a compile error. The one distinction it does
  not catch is U24 vs U32 (both uint32, range-only); that range is enforced by the
  parser and pinned by `RejectsOverflowTtl24Bit`.
- Producer validation: `tools/check_expect_keys.py` (CI `build-test`, alongside the
  wire/verdict `.def` gates) statically scans the producers' key LITERALS and fails
  if any (the orchestrator `dispatch.rs` + its generated `expect_surface.gen.rs`, and
  `dut_identity.py`) emits a key absent from the registry — i.e. a key the generated
  consumer would silently drop.

The producers stay hand-written: they map keys to deployment VALUES (vsomeip.json
paths, bash vars), which is producer-specific and not the schema's concern. The
correct SSOT boundary is therefore "registry is authoritative for accepted keys
(consumer generated); producers validated against it", not full producer
generation. `unit_tests/expect_parser_test.cpp` pins the per-kind parse/range
behaviour across all seven groups.

**Residual (honest scope).** This closes consumer-side omission, NOT producer-side:
if a producer FORGETS to emit a key a guard needs, the field stays at its 0
sentinel and the guard false-passes — the static producer scan checks
producer ⊆ registry, not registry ⊆ producer, so it cannot see a missing
emission. That residual is covered by per-scenario test design plus `config_test.rs`,
not by this schema.

**Update (post-cutover).** The drift surface has since SHRUNK. With the strangler
cutover the bash emitter (`smoke-test.sh`) and the runtime `parity-check.sh` key-set diff
were both retired, and the base `--expect` identity surface is single-sourced through
`tools/expect_surface.def` codegen (TD-12). The producers that remain are the Rust
orchestrator (`dispatch.rs` + generated `expect_surface.gen.rs`) and Python
(`dut_identity.py`), and the only static gate over them is `tools/check_expect_keys.py`
(producer ⊆ registry) plus `config_test.rs` — the runtime cross-driver diff is gone
because there is no longer a second driver to diff against.

---

## TD-04 — IPv4 header checksum mirrored across the C++ harness and the Python site tooling

**Status:** RESOLVED (2026-07-01 by TD-05). NARROWED 2026-06-30 to a single
cross-language Python mirror; that mirror was then eliminated when the site stopped
re-decoding the wire (TD-05). **Logged:** 2026-06-30 (surfaced by the TD-02 premise
audit).

**Update (2026-07-01).** The "irreducible" residual — `decode_pcap.py`'s
`ip_header_checksum_ok`, a Python re-implementation of the IPv4 header checksum — is
gone. `decode_pcap.py` was deleted (TD-05); the C++ exporter that replaced it emits
no per-frame `fields`, so the checksum is computed in exactly one place, the
`tc8::wire` RFC 1071 SSOT (`inetChecksumValid` / `tcpChecksumValid`), consumed by the
builders and the two verification sites. There is no second language re-summing the
bytes. The "floor only while the site re-decodes" framing below was the escape path;
TD-05 took it.

**What (now narrowed).** The RFC 1071 / RFC 793 checksum fold is a single C++ SSOT
(`tc8::wire::inetChecksum` / `tcpChecksum`, `src/wire/ip_checksum.*`), shared by every
builder AND — as of the narrowing — both verification sites:

- `src/sce_integration/ipv4_captured.h` `header_checksum_valid()` reconstructs the
  20-byte IPv4 header from the parsed scalar fields and calls
  `tc8::wire::inetChecksum(...) == 0` (no longer a hand-rolled fold).
- `src/dissect/packet_pipeline.cpp` calls `tc8::wire::tcpChecksum(...) == 0` over the
  captured segment (no longer a hand-rolled pseudo-header fold).

The ONLY remaining duplication is cross-language: `site/scripts/decode_pcap.py`
(`ip_header_checksum_ok`) independently sums the IPv4 header in Python. A C++ SSOT
cannot subsume a Python decoder, so this residual is irreducible by the wire-`.def`
or shared-helper mechanisms — it is the genuine, accepted remainder of TD-04. (The
TCP checksum has no Python twin and is now fully single-sourced in C++.)

**Risk if left.** Near-zero drift: RFC 791/793/1071 are frozen and the check is a
fixed algorithm, not a vendor-extensible layout. A divergence would only
mis-report a checksum on the site preview; the C++ stays authoritative.

**Why the residual stays — and why NOT an offset `.def`.** Within C++, the textbook
route IS now taken: both verifiers fold through the one `tc8::wire` checksum SSOT, so
the C++ algorithm is single-sourced (the narrowing). What cannot be collapsed is the
C++↔Python split: unlike SD/DHCP the two sides share no offset TABLE — the C++ folds
RFC 1071 over its reconstructed/captured bytes while Python sums the raw bytes in a
separate interpreter — so they share only the standard algorithm, which a `*_wire.def`
does not address and a C++ helper cannot cross into Python. Re-implementing RFC 1071
in two languages is the floor — but ONLY because the site re-decodes the wire at
all. Eliminating that (TD-05: make the C++ harness the single decoder/exporter so
the site renders pre-decoded JSON) would close this residual entirely. Until then,
tracked as a low-drift item (RFC frozen, C++ authoritative) so the TD-02 premise
stays truthful.

---

## TD-05 — the documentation site re-decodes the wire in Python, duplicating the C++ decoder

**Status:** RESOLVED (2026-07-01). The site no longer re-decodes the wire; it
replays each saved pcap through the harness's own decoder. This collapsed the
TD-01/02/04 Python mirrors (see the resolution + their update notes).
**Logged:** 2026-07-01 (surfaced by "why is there Python at all?").

**What.** The conformance harness is C++ and owns the authoritative wire decoder
(`src/dissect/` + `src/sce_integration/*_captured.h`). The documentation site
(`site/`, an Astro JS/TS static app at https://newmassrael.github.io/tc8-harness/)
renders per-case pcaps, and its data-prep step `site/scripts/decode_pcap.py` is a
SECOND, independent wire decoder in Python: it re-parses ARP / ICMPv4 / IPv4 / UDP /
TCP header fields (and the SD / DHCPv4 layouts via the `.def`-generated mirrors) into
the site's `PacketCapture` JSON (`site/src/lib/types.ts`). The same wire is decoded
twice — once in C++ for the verdict, once in Python for the web view.

This is the ROOT of the surviving Python mirrors tracked piecemeal as TD-01 (SD
wire), TD-02 (DHCPv4 BOOTP) and TD-04 (IPv4/TCP checksum): each single-sourced the
C++ side (or the `.def`), but a Python decode still exists BECAUSE the site
re-decodes at all.

**Why it exists.** A static documentation website is JS/TS, not C++; its pcap
data-prep was written in Python (the natural choice for pcap parsing + JSON). The
C++ harness already emits a per-event `<pcap>.trace.json` sidecar (`test_command.cpp`
`dumpTraceJson`; `appendCapturedJson` per `*_captured.h`) that `decode_pcap.py` partly
overlays — but the harness exports only the VERDICT-trace events, not the full
per-packet `PacketCapture` list the site renders, so `decode_pcap.py` still decodes
every frame itself.

**Risk if left.** Low drift: the wire layouts are RFC/spec-frozen, the `.def` gates
(`gen_*_wire.py --check`) + golden-vector self-tests keep the SD/DHCP mirrors honest,
and the C++ stays authoritative for verdicts (the Python only affects the web
preview). A divergence mis-renders a field on the site, never a verdict.

**Resolution.** The C++ harness is now the SINGLE decoder/exporter. A new offline
CLI mode, `tc8-harness decode-pcap` (`src/cli/decode_pcap_command.cpp`), replays a
saved pcap through the harness's own `dissect::PacketPipeline` — the authoritative
wire decoder that drives verdicts — and emits the site's `PacketCapture` JSON
(`site/src/lib/types.ts`): per-frame idx / timestamps / direction / endpoints /
protocol / human summary. CI (`pcap-refresh.yml`) calls it where it previously ran
`decode_pcap.py`. Consequences:

- `site/scripts/decode_pcap.py` (the second wire decoder) is DELETED, and with it
  the `.def`→Python generators (`tools/gen_someip_sd_wire.py`,
  `tools/gen_dhcpv4_wire.py`, `tools/wire_gen_common.py`), the generated mirrors
  (`site/scripts/*_wire_generated.py`), and their CI / pre-commit freshness gates.
  The `someip_sd_wire.def` / `dhcpv4_wire.def` SSOTs remain — now with a single C++
  consumer (`someip_captured.h` / `dhcpv4_wire.h` `#include` them), so there is no
  cross-language mirror left to keep in step. **This is what collapses TD-01, TD-02,
  and TD-04** (see their update notes).
- The site's timeline labels were already rendered from the harness transition trace
  (the `captured_trace` block, merged verbatim by the exporter), not from per-frame
  field re-evaluation — so `decode-pcap` emits no `fields` dict, and
  `generate_messages.py`'s dead dual-evidence cond-walker (its tokenizer / parser /
  `_eval` / per-protocol helpers / `_packet_view`, ~2.8k lines) was retired, leaving
  the trace-driven `_label_via_trace` path. The site is now pure presentation.

**Equivalence + drift gate.** The exporter was proven output-equivalent to the
retired `decode_pcap.py` on a synthetic capture spanning ARP / ICMPv4 / IPv4 / UDP /
DHCPv4 / TCP / SOME/IP (UDP + TCP) / SOME/IP-SD / Upper-Tester / unknown-ethertype:
identical idx / timestamps / direction / endpoints / protocol / summary and a
byte-identical `captured_trace` merge. The cond-walker retirement was proven
label-identical to the prior generator on a trace-backed case. That proof is now a
standing gate, not a one-time check: the `decode_pcap_golden` ctest
(`unit_tests/run_decode_pcap_golden.cmake`) replays a committed fixture pcap + trace
(`unit_tests/fixtures/decode_pcap_sample.*`) through the real binary on every build
and asserts the output is byte-identical to the committed expected JSON — the
automated guard that replaced the deleted `.def` `--check` freshness gates.

---

## TD-06 — Upper-Tester response field decode is duplicated (decode-pcap vs udp_captured.h)

**Status:** RESOLVED (2026-07-01). **Logged:** 2026-07-01 (cold review of TD-05).

**What.** The documentation-site exporter `src/cli/decode_pcap_command.cpp`
(`utSummary`) hand-decodes the Upper-Tester response body — the response-bit split,
status byte, and per-opcode trailers (e.g. `GetReceivedUdp` → received + src
ip/port/len, `CreateUdpReceivePorts` → actual count) — at the same wire offsets that
the authoritative verdict-path decoder `src/sce_integration/udp_captured.h`
(`fillUdpCapturedFromFrame`) already extracts into `ut_received` / `ut_recv_*` /
`ut_create_actual_count`. Two decoders for one wire format. Every other protocol the
exporter summarises routes through the single authoritative decoder (SD via
`fillSomeIpCapturedFromFrame`, the rest via the pipeline's `*Frame`); UT is the lone
hand-rolled re-decode, because the pipeline emits no UT event and `udp_captured.h`
covers only the subset of opcodes the verdict path needs.

**Why it exists.** TD-05 reused the verdict decoder wherever it already produced the
field; for UT, the exporter needs more opcodes (`QueryTcpInfo`, `QueryLLAddress`,
`QueryDhcpLease`, …) than `udp_captured.h` decodes, so the quick path was to decode
the whole UT response in the exporter rather than first factor a shared decoder.

**Risk if left.** Low drift: the UT protocol is the harness's OWN wire format, frozen
in `include/tc8/upper_tester_protocol.h` (which already owns the opcode/status value
SSOT and the `readU16` reader). A divergence mis-renders a UT row on the site, never a
verdict. The opcode/status NAMES and the response-bit/port constants are already
single-sourced; only the per-opcode trailer field OFFSETS are mirrored.

**Textbook fix.** Factor a shared `tc8::ut::decodeResponse(payload, len) -> struct`
into `upper_tester_protocol.h` (covering all opcodes), and have BOTH
`udp_captured.h` and the exporter consume it. The verdict struct keeps only the
fields it asserts on; the shared decoder owns the offsets.

**Why deferred (was).** The clean fix reaches into the verdict-path `udp_captured.h`, which
was out of TD-05's scope (the site-decoder elimination). Tracked here so the UT offset
mirror is not forgotten; the drift is low and the exporter output is gated
(`decode_pcap_golden`).

**Resolution (2026-07-01).** The textbook fix was taken: `tc8::ut::decodeResponse(payload,
len) -> UtResponse` in `include/tc8/upper_tester_protocol.h` is now the single owner of
the response wire offsets, covering every opcode the exporter renders. Both consumers
derive from it — the verdict path (`udp_captured.h` `fillUdpCapturedFromFrame`) copies the
subset it asserts on (`ut_received` / `ut_recv_*` / `ut_create_actual_count`) and keeps its
`src_port == kPort` gate on top; the exporter (`packet_summary.cpp` `utSummary`) reads the
full set. There is no second decoder for the UT wire format. IP fields come back in network
byte order (matching `UdpCaptured::ut_recv_src_ip`), so the exporter formats them through the
`tc8::sce::ipv4ToDotted` SSOT core and the near-duplicate `ipv4FromBe` formatter was deleted.
`udp_captured_test` pins the verdict subset; `packet_summary_test` pins the exporter output
(including `QueryTcpInfo`, an opcode the golden fixture does not carry); `decode_pcap_golden`
gates the rest end-to-end. All output is byte-identical to before the refactor.

---

## TD-07 — SOME/IP-SD message magic (service 0xFFFF / method 0x8100) has no named SSOT

**Status:** RESOLVED (2026-07-01). **Logged:** 2026-07-01 (cold review of TD-05).

**What.** The SD-message identity — header `service_id == 0xFFFF` and
`method_id == 0x8100` (PRS_SOMEIPSD) — is spelled as raw literals across the tree:
`src/sce_integration/someip_captured.h` repeats `service_id == 0xFFFF` in several
recognizers, the SD builder uses a function-local `kMethodIdSd = 0x8100`, the case
bodies write `0x8100` inline, and TD-05's `decode_pcap_command.cpp::someipIsSd` adds
one more spelling of the full predicate. There is no shared `kSdServiceId` /
`kSdMethodId` constant and no shared `isSdMessage(frame)` recognizer.

**Why it exists.** Pre-existing scatter; SD detection grew per-site. TD-05 routed the
message-type / return-code parts of `someipIsSd` through the `someip::MessageType` /
`ReturnCode` enums but left `0xFFFF` / `0x8100` raw, matching the surrounding
convention rather than introducing a half-used constant.

**Risk if left.** Low: the SD magic is RFC-frozen and a wrong literal would fail
loudly in tests. The cost is readability + a missing single recognizer, not drift.

**Textbook fix.** Promote `kSdServiceId = 0xFFFF` / `kSdMethodId = 0x8100` to
`src/someip/protocol.h` (next to the message-type/return-code enums) and add a shared
`isSdMessage()` helper, then repoint the captured recognizers, the dispatcher gate,
the builder, and the exporter at it.

**Why deferred (was).** A cross-cutting SSOT unification spanning the verdict path, the
builder, and the cases — broader than TD-05's site-decoder scope. Logged so the
scatter is visible.

**Resolution (2026-07-01).** `src/someip/protocol.h` (the neutral SOME/IP constant leaf,
next to the message-type/return-code enums) now owns `kSdServiceId = 0xFFFF`,
`kSdMethodId = 0x8100`, and the `isSdMessageId(service_id, method_id)` recognizer. The raw
literals were repointed at it: the captured recognizers + SD parse gate
(`someip_captured.h`, which gate on the Service ID alone), the SD builder
(`someip_sd_builder.cpp` `appendSdHeader` default + the retired function-local `kMethodIdSd`),
the ETS_137 hand-built SD frame (`putBe16(kSdServiceId)`/`putBe16(kSdMethodId)`), and the
exporter (`packet_summary.cpp` `someipIsSd`, which uses the full pair via `isSdMessageId`).
The FindService "any service" wildcard (`want_service_id == 0xFFFF`) is a distinct concept
and was intentionally left as-is. There is no runtime dispatcher gate on the SD Method ID in
first-party code (the ETS_178 comment refers to the vendored vsomeip dispatcher). Values are
unchanged, so behaviour is byte-identical (`someip_captured_test` / `someip_sd_builder_test` /
`ets_emission_test` / `decode_pcap_golden` all pass unchanged).

---

## TD-08 — decode-pcap protocol-presentation tables live in the CLI translation unit

**Status:** RESOLVED (2026-07-01). **Logged:** 2026-07-01 (cold review of TD-05).

**What.** The display-name tables (`someipMsgTypeName`, `someipReturnCodeName`,
`sdEntryTypeName`, `icmpTypeName`, `dhcpMsgTypeName`, …) and the per-protocol summary
builders live in the anonymous namespace of `src/cli/decode_pcap_command.cpp`. They
are reusable protocol-presentation logic, but as command-local statics they cannot be
unit-tested in isolation (only end-to-end via `decode_pcap_golden`) and a future
`tc8-harness live` / `replay` text renderer could not reuse them without forking.

**Why it exists.** TD-05 built the exporter as one self-contained command; the
presentation helpers were written inline rather than extracted to a shared header.

**Risk if left.** Low: no drift hazard (single consumer today). The cost is testability
+ a potential future fork if another renderer needs the same labels.

**Textbook fix.** Move the name tables + summary builders to a `someip/`-adjacent
presentation header next to the enums they name; leave `decode_pcap_command.cpp` as
JSON assembly + endpoint autodetect + the offline drive loop, and add a direct unit
test of the summary builders.

**Why deferred (was).** A restructure with no behavior change; the command-local form is
defensible while there is a single consumer. Logged for the day a second text renderer
lands.

**Resolution (2026-07-01).** The presentation layer was extracted to
`src/cli/packet_summary.{h,cpp}`: the display-name tables + formatting helpers (now in the
`.cpp` anonymous namespace), the per-protocol summary builders, `someipIsSd`, the `Candidate`
struct, and `makeCandidate`. `decode_pcap_command.cpp` keeps only JSON assembly, endpoint
auto-detection, and the offline drive loop. The builders are now unit-testable in isolation —
`unit_tests/packet_summary_test.cpp` asserts them directly (and any future `live`/`replay`
text renderer can reuse the header). `packet_summary.cpp` is strict-gated (it joins the
`tc8_harness_testable` library and the main binary). No behaviour change: `decode_pcap_golden`
is byte-identical.

---

## TD-09 — decode-pcap has minor, accepted display divergences from the retired Python decoder

**Status:** RESOLVED (2026-07-01). **Logged:** 2026-07-01 (cold review of TD-05).

**What.** Three small per-frame summary divergences from the deleted `decode_pcap.py`,
all display-only (labels, never verdicts):

- **SD entry/option counts cap at 8.** `sdSummary` iterates `sd_entry_count` /
  `sd_option_count`, which `fillSomeIpCapturedFromFrame` caps at
  `kMaxSdEntries`/`kMaxSdOptions` (= 8). An SD frame carrying >8 entries shows
  `+N more` / `ipv4_endpoints=` undercounted relative to the true wire total (the
  Python counted the real totals). TC8 SD frames carry 1–2 entries and the one
  high-fan-out case is `trim_pcap.py`-trimmed, so this is rare.
- **Sub-240-byte DHCP renders as plain UDP.** The pipeline only emits a `Dhcpv4Frame`
  when the BOOTP body reaches the magic-cookie offset (240 B); a shorter datagram on
  port 67/68 shows as `UDP src→dst, len=N` where the Python showed
  `DHCPv4 (truncated, N B)`. Such a frame is malformed DHCP.
- **Other-protocol IPv4 byte count.** For an IPv4 packet whose upper protocol is not
  ICMP/UDP/TCP, the summary uses the IP header `total_length`; the Python used the
  captured byte length. They differ only under L2 padding or snaplen truncation
  (the C++ form is arguably the more correct one).

**Why it exists.** The first two follow from reusing the pipeline's verdict-oriented
decode (bounded SD arrays; DHCP gated at the cookie offset) rather than re-deriving a
display-only decode; the third is a deliberate choice of the spec-meaningful length.

**Risk if left.** Negligible: display-only, on rare/malformed frames, and the exporter
output is gated (`decode_pcap_golden`).

**Textbook fix.** For the SD cap, surface the pre-cap totals from
`fillSomeIpCapturedFromFrame` (a verdict-struct change) or annotate the count as
capture-capped; for sub-240 DHCP, recognise the 67/68 port pair in the exporter and
label it truncated.

**Resolution (2026-07-01).**

- **SD count cap.** `SomeIpCaptured` gained two DISPLAY-ONLY uncapped on-wire totals —
  `sd_entry_count_wire` and `sd_ipv4_endpoint_count_wire` — populated by `parseSdHeaderInto`
  (entries = declared entries-array length / 16) and `parseSdOptionsInto` (which now keeps
  walking past the parse cap purely to tally the endpoints, storing only up to
  `kMaxSdEntries`/`kMaxSdOptions`). Every verdict-facing count is byte-identical;
  the new fields are documented as display-only and MUST NOT be used by guards. `sdSummary`
  now derives "+N more" and `ipv4_endpoints=` from the wire totals, so a frame exceeding the
  cap is no longer undercounted. `packet_summary_test` pins this with a 10-entry frame
  (parse cap 8 → "+7 more").
- **Sub-240 DHCP.** `makeCandidate` labels a datagram on the 67/68 port pair that the
  pipeline did not raise as a `Dhcpv4Frame` as `DHCPv4 (truncated, N B)` instead of plain
  UDP. Covered end-to-end by a new sub-240 fixture frame in `decode_pcap_golden` and
  directly by `packet_summary_test`.
- **Other-protocol IPv4 byte count.** Kept as-is: the exporter's use of the IP header
  `total_length` is the spec-meaningful length and is arguably more correct than the retired
  Python's captured-byte count (they differ only under L2 padding / snaplen truncation). This
  is now a deliberate, documented choice rather than an unexamined divergence.

---

## Cold-review remediation of TD-06..TD-09 (2026-07-01)

A three-reviewer cold audit of the TD-06..TD-09 work found real compromises; all
were remediated (build 0-warn, ctest green). Recorded here so the register stays
honest about what the first pass got wrong.

- **DHCP ports 67/68 had no SSOT** (the TD-09 site-decoder re-spelled the pipeline's
  port-pair predicate as raw literals). Promoted `kDhcpServerPort` / `kDhcpClientPort`
  and a shared `isDhcpPortPair` recognizer to `include/tc8/protocol_frames/dhcpv4_frame.h`;
  the dissect pipeline gate, the exporter, the DHCP frame builder, and the BPF filter
  strings all route through it.
- **`decodeResponse` "single owner" was overstated** — the active-control path
  (`dut_control.h`) hand-decoded the same UT response offsets. Factored
  `tc8::ut::decodeResponseBody` as the offset owner; `dut_control.h` (QueryTcpInfo,
  QueryTcpEstablished, ReceiveTcpData/Oob) now derives from it. Also renamed the
  transport-result struct to `tc8::stimulus::UtReply` to end the same-name clash with
  `tc8::ut::UtResponse`, and `decodeResponse` no longer applies response offsets to a
  request payload.
- **SD-magic predicate half-done** — added `SomeIpCaptured::headerIsSd()` and routed the
  verdict recognizers + SD-fill gate through it; added `kSdEntrySizeBytes` for the SD entry
  stride.
- **`sd_entry_count_wire` was a blind `declared/16`** (over-reported truncated frames, could
  overflow u16). Now counts entries actually present, bounded like the options walk. Covered
  by new `packet_summary_test` cases (truncated entries; >8 endpoint options).
- **ARCH: the authoritative SD decoder lived in the verdict layer** (presentation reached up
  into `sce_integration`). Extracted the SD structs / value namespaces / `parseSdInto` into
  the neutral leaf `src/someip/sd_decode.h`; `SomeIpCaptured` mixes in `SdDecoded` as its
  "SD aspect" (source-transparent to cond/case code), and the documentation-site exporter
  decodes a standalone `SdDecoded` — so presentation depends DOWN, the wire is decoded once,
  and the display-only wire totals live on the decode result, not the verdict DTO. Moved the
  supporting `someip_sd_wire.def` and `wire_read.h` to neutral homes (`src/someip/`,
  `src/wire/`). Per-frame candidate selection moved to `packet_summary.cpp::chooseFrameView`,
  so the decode-pcap command TU keeps only I/O + JSON assembly.

---

## TD-10 — decode-pcap format cores still live in the verdict-path Evidence-Export header

**Status:** RESOLVED (2026-07-03 — cores moved to the neutral wire leaf). **Logged:**
2026-07-01 (cold-review residual).

**Resolution (2026-07-03).** Done as the "textbook fix" below. `macToHex` / `ipv4ToDotted` moved
from `src/sce_integration/captured_trace.h` (the Evidence-Export / verdict layer, `tc8::sce`) to
the existing neutral leaf `src/wire/wire_format.h` (`tc8::wire`, beside `readBe` / the ip-checksum
cores). `captured_trace.h`'s `appendMacJson` / `appendIpv4Json` now delegate to `tc8::wire::`, and
the two direct consumers are repointed: the decode-pcap exporter (`decode_pcap_command.cpp`) and
`packet_summary.cpp` — the latter now drops `#include "sce_integration/captured_trace.h"` entirely,
so presentation (cli/) no longer reaches UP into `sce_integration` purely for formatting (the last
ARCH-A layering thread this debt tracked). `appendJsonEscaped` stayed in `captured_trace.h` (a JSON
concern the exporter still uses). Behavior-preserving: 0-warning build + ctest 66/66, including the
`decode_pcap_golden` gate that byte-diffs the exporter's JSON output. The prose below is the
original finding.

**What.** The generic wire-formatting cores `ipv4ToDotted` / `macToHex` (and the JSON
`appendJsonEscaped`) live in `src/sce_integration/captured_trace.h` (the Evidence-Export
layer) in namespace `tc8::sce`, yet the documentation-site presentation
(`cli/packet_summary.cpp`) and the decode-pcap command consume them — so presentation still
`#include`s up into `sce_integration` for formatting, the one remaining thread of the ARCH-A
layering critique (the SD *decoder* was relocated; these *formatters* were not).

**Risk if left.** None functional: they are already a single definition (SSOT), so there is
no drift — this is purely a file-home / layering nit. Presentation output is unchanged.

**Textbook fix.** Move `ipv4ToDotted` / `macToHex` to a neutral leaf (e.g. `src/wire/`),
have `captured_trace.h` delegate its `appendMacJson`/`appendIpv4Json` to them, and repoint
the ~3 direct consumers (exporter, command, `test_runner.h`). `appendJsonEscaped` is a JSON
concern and can stay with the JSON helpers.

**Why deferred.** The move crosses `test_runner.h` (verdict path) and `captured_trace.h`
(included by ~10 `*_captured.h`), i.e. a third verdict-path touch in one session. Since the
cores are already SSOT, this is polish with no correctness stake, best done as a focused,
independently-verified change.

---

## TD-11 — the topology extra-expect channel has no automated cross-driver parity coverage

**Status:** RESOLVED (2026-07-03), then DEBT DISSOLVED by the 2026-07-18 cutover. **Logged:**
2026-07-01 (added with the extra_expect channel).

**Update (post-cutover 2026-07-18) — DEBT DISSOLVED.** The 2026-07-03 gate below
(`parity-check.sh --identity-only`, run by a `build-test.yml` step) was REMOVED with the
strangler cutover that retired the bash driver. The debt is now moot: `smoke-test.sh` is
gone, so the extra_expect channel has a SINGLE producer (the orchestrator's `.toml` via
`site.rs`) — there is no second hand-mirrored `.conf` to drift against, so nothing to
cross-diff. The example `.conf`/`.toml` pair and the gate were dropped. The 2026-07-03
resolution and the original finding below are historical.

**Resolution (2026-07-03).** The "blocked on the self-hosted runner" premise was too pessimistic:
the extra_expect PARITY is observable in the UNPRIVILEGED `--print-expect` dump — both drivers fold
the tokens into it and exit before any netns / provisioning — so it does not need the sudo
case-disposition path that gates `parity-check.yml`. Closed on the HOSTED leg: an example conf pair
(`dut/env/topology.d/examples/extra-expect-parity.conf` + `dut/env/orchestrator/examples/extra-expect-parity.toml`)
declares identical bare extra_expect tokens; `parity-check.sh --identity-only` (new flag) runs just
the `--print-expect` diff; and a new `orchestrator` job in `build-test.yml` runs it on every push —
also building and `cargo test`-ing the orchestrator, which previously had NO auto-triggered CI
(parity-check.yml is manual + self-hosted). Proven to fire: matched confs PASS, a drifted `.toml`
token value FAILs the gate. The broader full case-disposition parity (`parity-check.yml`) still
awaits the runner NOPASSWD provisioning, but that is a separate strangler concern, not the
extra_expect-channel coverage gap this debt named. The prose below is the original finding.

**What.** The `--topology-conf` extra-expect channel — bash `TC8_TOPOLOGY_EXTRA_EXPECT`
(`dut/env/smoke-test.sh`) and Rust `extra_expect` (`dut/env/orchestrator/src/site.rs`) — is
folded into each driver's `--expect` surface, but no in-tree topology conf sets it, and
`parity-check.yml` is `workflow_dispatch` (manual) running only the default confs. So the
channel has zero automated cross-driver parity coverage: only per-side unit tests and a
manual `--print-expect` diff exercise it.

**Risk if left.** A site that uses the channel keeps two hand-mirrored confs (bash `.conf`
array vs Rust `.toml` list) that can drift, or a fold-position change on one driver can
diverge, with no gate catching it. `--print-expect` strips `--expect`, so a mis-authored
token can pass the print dump yet be wrong at run time.

**Textbook fix.** Commit an example conf pair declaring identical bare `extra_expect`
tokens, add a `dut/env/orchestrator/parity-check.sh` scenario diffing both drivers'
`--print-expect` for it, and — once the self-hosted runner NOPASSWD entry is provisioned —
make `parity-check.yml` push-triggered so the channel is gated on every change.

**Why deferred.** The channel's real values live in an external OEM `--topology-conf` (out
of tree); an in-tree example plus a parity scenario is net-new test infrastructure, and the
CI auto-trigger is blocked on runner provisioning. Registered so the coverage gap is a
conscious, tracked deferral rather than an oversight.

---

## TD-12 — the base `--expect` identity surface is hand-mirrored across the bash and Rust drivers

**Status:** RESOLVED (2026-07-03 — single-sourced via codegen). **Logged:** 2026-07-01
(surfaced by the tester_ipv4 drift).

**Update (2026-07-19, `dcaf968a`).** The strangler cutover later retired the bash
`smoke-test.sh` driver — the orchestrator is now the sole driver — so the bash mirror
`dut/env/expect_surface.gen.sh` and its emit path in `gen_expect_surface.py` were removed;
only `expect_surface.gen.rs` is generated now, and `check_expect_keys.py` no longer scans the
bash file. `tools/expect_surface.def` stays the structured SSOT. This is exactly the
single-driver end state the "Textbook fix" note below predicted, so the fix carries forward
unchanged — the RESOLVED prose below describes the two-driver world as it stood in 2026-07-03.

**Resolution (2026-07-03).** Done as the "textbook fix" below. The key->source list is now
single-sourced in `tools/expect_surface.def` and GENERATED into both drivers by
`tools/gen_expect_surface.py` (mirroring `gen_wire_manifest.py`): `dut/env/expect_surface.gen.sh`
(bash `tc8_expect_<bucket>` functions that assign the `TC8_*_EXPECT` arrays / print the runtime
DUT-MAC block) and `dut/env/orchestrator/src/expect_surface.gen.rs` (`append_someip_identity` /
`append_l2l3_identity` + `RUNTIME_MAC_KEYS`, include!-d into dispatch.rs). Both drivers consume the
generated surface instead of hand-listing it, so adding a key is a one-line manifest edit that
reaches BOTH drivers — they cannot diverge by construction. Manifest source kinds (`vs_id` /
`vs_sd` / `wire` / `wire_alias` / `dut_ip` / `tester_ip` / `dut_mac`) map each key to its per-
language value expression; only the `--topology-conf` extra_expect fold and the conditional
`arp_stimulus.ut_cache_conditioning_s` stay as small hand-written glue (control flow, not a static
key->source list). A `gen_expect_surface.py --check` freshness gate is wired into the build-test CI
leg beside the wire-manifest gate — it runs on the hosted leg, so unlike TD-11's parity CI it is
NOT blocked on the self-hosted runner provisioning; `check_expect_keys.py` now scans the generated
files so the key-schema gate keeps its coverage. Byte-exact parity was proven: both drivers'
`--print-expect` dumps are identical to the pre-refactor golden (single-pc + lwip-tap) and to each
other, at 0 warnings and 46/46 orchestrator unit tests. The per-key
`expect_args_emits_tester_ipv4_mirroring_bash` guard is kept as a regression test (its motivating
gap is now impossible by construction). Spec-section (§) citations stay in the hand-edited drivers,
not the generated files, to keep the mnemosyne section bindings stable. The prose below is the
original finding.

**What.** The ~30-key per-case `--expect` identity surface is emitted twice, by hand: bash
`init_expectation_defaults`'s `TC8_DUT_EXPECT` (`dut/env/smoke-test.sh`) and Rust
`expect_args` (`dut/env/orchestrator/src/dispatch.rs`). The two are kept in lockstep only by
`parity-check.sh` plus the `dut_identity_py_matches_rust_parser` pin — both non-blocking in
CI.

**Risk if left.** Silent drift. This already happened: `tester_ipv4` was added to bash-only
(commit 8408690c) and the orchestrator never mirrored it; the gap sat undetected until this
session because the gate is manual. The per-key guard
`expect_args_emits_tester_ipv4_mirroring_bash` is a symptom patch — the next bash-only key
re-opens the same class.

**Textbook fix.** Single-source the base surface so bash and Rust cannot diverge by
construction: derive both drivers' emission from one artifact (e.g. generate the key/value
list from `tc8_expect_keys.def` + `vsomeip.json`). This is the strangler's natural end
state — after cutover only the Rust emitter remains, and it should read the surface, not
hand-list it.

**Why deferred.** It touches the entire parity surface (every identity key on both drivers),
so it is a focused refactor of its own, not a rider on the extra_expect feature. Deferring
keeps this session's change scoped; the debt records the root cause the extra_expect channel
and the tester_ipv4 mirror both work around.

---

## TD-13 — the warm-re-offer signal polls a counter instead of the in-tree Waker primitive

**Status:** RESOLVED (2026-07-02). **Logged:** 2026-07-01 (3-cold-reviewer review of the
`IEtsExtension::onReactivate` hook).

**Resolution (2026-07-02).** Done as the "textbook fix" below when the pre-registered
trigger fired: adding `IEtsExtension::onSuspend` (the second lifecycle transition) replaced
the polled counter + `ResumeEdge` with a single Waker-backed `LifecycleSignal`
(`dut/dut_service/lifecycle_signal.h`). The detached suspend thread post()s Suspend (on the
StopOffer) / Reactivate (on the paired re-offer); the DUT main loop folds the Waker's fd into
`PollableHost::drainReady` via a small `IPollableService` adapter (`LifecycleDispatcher` in
`dut_main.cpp`) and dispatches both hooks on the main thread — FIFO-ordered, lossless, and
prompt (woken on the eventfd, not noticed on the next tick poll). `ResumeEdge` and its test
are retired; `lifecycle_signal_test` covers the channel. The prose below is kept for the
rationale that led here.

**What it was** (all symbols named below were removed by the resolution above — kept in past
tense for the rationale record). The warm `suspendInterface` re-offer signal was delivered by
the detached suspend thread bumping a monotonic `std::atomic<uint32_t>` counter
(`ServerRole::resumeCount()`), which the DUT main loop (`dut/dut_service/dut_main.cpp`) polled
once per pass through a `ResumeEdge` edge-detector (`dut/dut_service/resume_edge.h`) to fire
`onReactivate` on the main thread. The repo already ships a purpose-built cross-thread wake primitive for exactly
"a detached thread must signal a poll() loop" — `tc8::testability::Waker`
(`src/testability/io_multiplexer.h`; POSIX eventfd + lwIP loopback-UDP backends,
`EventfdWaker` in `dut/dut_service/linux_socket_backend.cpp`) — used by the testability
`Reactor`, and the DUT main loop already folds `IPollableService::pollFd()` into its `poll()`
set via `PollableHost::drainReady`. The event-driven delivery is thus buildable from parts
already in tree; the hook instead adds a second, polled idiom for the same problem.

**Why it exists.** The DUT main loop is a TICK-CADENCE loop by identity: `onTick` fires on a
~200 ms cadence and the loop already polls `g_stop` and a `next_tick` cursor each pass. A
polled resume counter is consistent with THAT loop's idiom, costs one atomic load per
existing pass (no extra syscall — `drainReady`'s timeout is already bounded by `next_tick`),
and delivers `onReactivate` within the same cadence it already delivers `onTick`. The `Waker`
is the idiom of the DIFFERENT, event-driven `Reactor` loop.

**Risk if left.** Low and bounded. Delivery latency is <= one tick window (~200 ms), itself
dominated by the irreducible vsomeip async offer skew (`registerService()` returning true does
not mean the wire OfferService is out yet), so an event-driven wake would not make the signal
wire-tight anyway. The counter also does NOT GENERALIZE: an `onSuspend` (fire on the stop half)
would add a parallel counter + shadow + poll triple, and a client-only re-activation signal has
no `ServerRole` to source from — each new lifecycle transition duplicates the pattern, where a
single Waker + a small lifecycle-event channel would be additive. There was no correctness
hazard (SSOT-clean, race-free, wrap-safe, was unit-tested by the former `resume_edge_test`).

**Textbook fix.** Give `ServerRole` a `Waker` (captured by shared_ptr copy, the same lifetime
discipline as `resume_seq_`), `signal()` it from the detached suspend thread on a successful
re-register, fold its `pollFd()` into `dut_main`'s `drainReady` poll set through a small
`IPollableService` adapter (the interfaces differ: `Waker` is `pollFd/signal/drain`,
`IPollableService` is `pollFd/onReadable`), and dispatch `onReactivate` when it drains — plus a
lifecycle-event enum so `onSuspend` / future transitions ride one channel. This makes
`onReactivate` as prompt as an adopted receiver and single-sources the "signal a poll loop"
mechanism on the repo's canonical primitive.

**Why deferred.** Genuinely debatable, not a clear defect: the polled counter is SSOT-clean,
race-free, unit-tested, and consistent with the cadence loop's own identity, and the latency it
accepts is dominated by vsomeip async skew. The Waker rework adds cross-cutting wiring (a socket
backend into `ServerRole`, a `Waker` <-> `IPollableService` adapter) for a promptness gain the
motivating CAN start-offset case does not clearly need. Registered so the second-idiom /
non-generalizing shape is a conscious, tracked choice; revisit when a second lifecycle
transition (`onSuspend`) or a client-only re-activation case lands — that is when the Waker's
generality pays for itself.

## TD-14 — the SD port (30490) is still hand-copied across C++ despite the wire SSOT

**Status:** RESOLVED (2026-07-02). **Logged:** 2026-07-02 (review of the utm_test
`TC8_WIRE_SD_PORT` request); resolved same day in a session-review audit that found the
"touches coverage-owned case files" deferral rationale was false for `client_mode.cpp`
(DUT firmware in `namespace tc8::dut`, not a case file — a same-namespace shadow of the
SSOT symbol). All sites already reached `dut_config.h`, so the fix was zero-cost: the two
`kSdPort` shadows (`client_mode.cpp` — which also shadowed `kSdMcastGroup`, fixed too — and
`someip_ets_152.h`) were deleted and the ~8 case-header `30490` literals routed through
`tc8::dut::kSdPort`. The one wire-byte fixture (`someip_ets_117.h` `0x77,0x1A`) keeps its
literal bytes (that IS the asserted wire image) but is now `static_assert`-tied to
`tc8::dut::kSdPort` so a retune cannot silently diverge. `kCapturePortLow` was left
independent: a BPF window bound is a distinct fact from the SD port, so coupling them would
be over-fitting, not SSOT. The prose below is the original finding.

**What it is.** `feat(wire)` (`3802a61e`) added `TC8_WIRE_SD_PORT` to the cross-language wire
manifest with a `cpp=include/tc8/dut_config.h:kSdPort` annotation, so the bash/Rust side is now
drift-gated against the canonical `tc8::dut::kSdPort`. That closes the shell overlay's hand-copy
but NOT the C++ side: the value 30490 is still spelled directly in several first-party TUs that
do not route through `tc8::dut::kSdPort`, so the wire gate cannot see them —
  - two LOCAL redefinitions shadowing the canonical symbol: `constexpr std::uint16_t kSdPort =
    30490;` in `src/sce_integration/cases/someip_ets_152.h` and `dut/dut_service/client_mode.cpp`;
  - ~8 bare `params.tester_endpoint.port = 30490U;`-style literals in ETS case headers
    (someip_ets_110/118/119/137/152/154/162/163.h) plus the big-endian byte form `0x77, 0x1A`
    in someip_ets_117.h.
(`dut_config.h`'s `kCapturePortLow = 30490` is a DELIBERATE relationship — the capture range
begins at the SD port — not a blind copy, and is out of scope here.)

**Why it exists.** The wire-manifest request was scoped to the topology overlay's shell hand-copy;
fixing that is one line. The C++-side literals predate the manifest and span case files owned by
the coverage work. `stimulus::someip_sd_builder` already routes through `tc8::dut::kSdPort`
correctly — the debt is confined to case-local endpoint fills and the two shadows.

**Risk if left.** Low, drift-safe in practice — 30490 is the registered SD port and every site
agrees today. But the two shadow `kSdPort` consts are genuine SSOT violations (a retune of
`tc8::dut::kSdPort` would silently diverge from them), and the literals are the exact hand-copy
class the wire manifest exists to kill.

**Textbook fix.** Replace the two local `kSdPort` shadows and the ~8 case-header literals with
`tc8::dut::kSdPort` (already the single home, `#include "tc8/dut_config.h"`), leaving one C++
SSOT that the wire manifest's `cpp=` annotation gates. Mechanical, but touches coverage-owned
case files, so deferred out of the one-line manifest change rather than bundled with it.

## TD-15 — the raw client onResponse correlates by session but not by interface version

**Status:** RESOLVED (2026-07-03 — stock default: NO major check) + OPT-IN STRICT MODE added
(2026-07-05) for conformance profiles that require it. The default behaviour is UNCHANGED — the
strict mode is off unless explicitly gated on. **Logged:** 2026-07-02 (session-correlation seam
for the client reaction path).

**Addendum (2026-07-05) — opt-in strict interface-version correlation.** The 2026-07-03 finding
below STANDS AS THE DEFAULT: a stock CommonAPI-SomeIP proxy and stock vsomeip both ignore a
session-correlated Response's major, so the raw client's default is session-only, unchanged.
Separately, some conformance profiles require a DUT-as-client to ignore a Response whose
Interface Version is wrong and let the call abort by timeout. That requirement and its
provenance belong WITH THOSE PROFILES, not restated in this public core. To satisfy it without
touching the stock default, `ResponseCorrelation` gained an OPT-IN flag
(`strict_interface_version`, constructor-injected): OFF (default) = the 2026-07-03 behaviour;
ON = a session-correlated Response whose major does not match its Request's is also dropped
(the correlation consumed), so the call aborts by timeout. `VsomeipEtsClientControl` reads the
flag from a neutral env gate (`TC8_DUT_STRICT_RESPONSE_INTERFACE_VERSION`, default off, set by
the profile's own run) so the pure policy stays env-free. `acceptResponse` gained a
`response_major` argument; a correctly-majored reply is delivered untouched (raw Return-Code
model preserved). `unit_tests/response_correlation_test.cpp` covers both modes. This is NOT the
make-it-pass hazard this debt guarded against: the default is stock-faithful and unchanged, and
the strict behaviour is active only where a profile explicitly gates it on.

**Resolution (2026-07-03).** The textbook fix's first step — "confirm against a real
CommonAPI-SomeIP proxy whether a correctly-correlated Response is rejected on major-version
mismatch" — was carried out against the actual stack the DUT is modelled on, and the answer
is NO. Two authoritative layers both ignore an incoming Response's Interface Version:
  - **CommonAPI-SomeIP 3.2.4** (`capicxx-someip-runtime` @ `86dfd698`,
    `src/CommonAPI/SomeIP/Connection.cpp::handleProxyReceive`) correlates a Response purely by
    `get_session()` into `asyncAnswers_` / `sendAndBlockAnswers_`, derives `CallStatus` from
    `get_return_code()` alone, and never reads `get_interface_version()`. An exhaustive sweep of
    the runtime puts every `major`/interface-version touch on the SEND / subscribe / build side
    (plus the queryable `InterfaceVersionAttribute`) — none on the Response-receive path.
  - **vsomeip** (`application_impl::on_message`) dispatches a Response to handlers via
    `find_handlers(service, instance, method)` — keyed on (service, instance, method) with no
    version dimension; the only version-adjacent gate is the `MT_NOTIFICATION` subscription-active
    check. CommonAPI registers its handler as `register_message_handler(service, instance,
    ANY_METHOD, ...)`, so nothing upstream filters the Response by version either.
Therefore the raw client's current behaviour — deliver a correctly session-correlated Response
regardless of its major byte — is FAITHFUL to the real proxy, and folding a version drop into
`ResponseCorrelation` would have fitted the harness to a property real middleware does not have
(the make-it-pass hazard this debt was logged to prevent). **No client change is made.** Per the
"if no" branch: a case that asserts a DUT *client* ignores a wrong-interface-version *Response*
is asserting a non-existent middleware property — the SOME/IP `E_WRONG_INTERFACE_VERSION` (0x08)
check is performed by the receiver of a *Request* (a server/DUT-as-server), not by a client
validating a Response — so it belongs in case authoring / spec reading, not this seam. The
`response_correlation.h` header comment is updated from "unconfirmed" to this confirmed finding.
The prose below is the original finding.

**What it is.** `ResponseCorrelation` (`dut/dut_service/response_correlation.h`) makes the raw
vsomeip client (`VsomeipEtsClientControl`) drop a Response whose SOME/IP Session ID matches no
Request the DUT sent — restoring the request-id correlation a CommonAPI-SomeIP proxy does, so the
client ignores an uncorrelated Response and the pending call times out. It deliberately does NOT
also drop a Response whose Interface Version (major) differs from the Request's, though vsomeip
delivers such a Response to the bare (service, instance, method) handler just the same (vsomeip
version-checks only OUTGOING requests against service availability — `routing_manager_client::send`
— never an incoming Response).

**Why it exists.** Session correlation is well-founded: the request-id (client + session) is the
canonical Response-to-Request key, and a wrong-session Response genuinely finds no pending call on
a real proxy. Interface-version rejection is a SEPARATE, unconfirmed property: it is not clear that
a real CommonAPI-SomeIP proxy rejects a CORRECTLY session-correlated Response on major mismatch (it
correlates by request-id, not by re-checking the response major). Folding a version drop into the
raw client would risk fitting the harness to a property real middleware may not have — a make-it-
pass rather than a faithful model. Scoped out until that proxy behaviour is confirmed.

**Risk if left.** A client reaction case that asserts the DUT ignores a wrong-interface-version
Response (session otherwise correct) is not enforceable through this seam yet — the raw client
delivers it, the DUT records success, the case cannot pass. Confined to that malformation; the
session-ignore property (the more fundamental one) is covered.

**Textbook fix.** Confirm against a real CommonAPI-SomeIP proxy whether a correctly-correlated
Response is rejected on major-version mismatch. If yes, extend `ResponseCorrelation` to store each
Request's major alongside its session and reject a Response whose `get_interface_version()` differs
— the record/accept API already carries the key, so this is additive. If no, the property belongs
in the case authoring / spec reading, not the harness client.

---

## TD-16 — "insufficient privilege" has no PRS_TPSP result code, so it reaches the wire as E_NOK

**Status:** OPEN (accepted). **Logged:** 2026-08-28, alongside the change that gave the
neighbor/multicast seam a status vocabulary (`include/tc8/net/op_status.h`).

**What it is.** The six capability operations on `net::SocketBackend` answer a
`net::OpStatus` that names WHY they failed, and `testability::ridFromOpStatus`
(`include/tc8/testability_protocol.h`) projects that onto a PRS_TPSP §6.8 Result ID. Four of
the six statuses reach a distinct code — `Ok` → E_OK, `UnknownInterface` → E_IIF,
`InvalidArgument` → E_INV, `Unsupported` → E_NTF. `NotPermitted` does not: it shares E_NOK
with the residual `Failed`. A test system therefore still cannot distinguish, FROM THE WIRE
ALONE, "the target could do this but the UTM process lacks CAP_NET_ADMIN" from "it was
attempted and failed for some other reason".

**Why it exists.** PRS_TPSP §6.8 defines no privilege code. The available vocabulary is
E_OK / E_NOK, the testability-specific E_NTF / E_PEN / E_ISB / E_INV, and the
primitive-specific E_ISD / E_UCS / E_UBS / E_IIF — none of which means "insufficient
privilege". Minting one would mean an AUTOSAR-specific code in the 0x02..0x7F range, i.e. a
wire value this repository invents. The sibling seam (`testability::SocketBackend`, via
`ridFromIfaceErrno`) already folds EPERM into E_NOK for the same reason, so folding here
keeps the two seams consistent instead of giving one of them a private code.

**Risk if left.** Bounded, and smaller than what it replaced. The distinction the originating
report needed — an operator's mistake (E_IIF) versus a permanent platform limit (E_NTF) — IS
now on the wire. What stays ambiguous is a privilege problem versus a generic failure, and
both are conditions of the deployment rather than of the target's capability. The distinction
is NOT lost in-process: the backend returns `OpStatus::NotPermitted` and a module can log it
via `net::toString`; it is only unrepresented on the wire.

**Textbook fix.** Two independent halves, either of which closes it:
1. An OEM profile that owns a 0x02..0x7F allocation defines a privilege code and changes the
   single `NotPermitted` arm of `ridFromOpStatus`. The projection is deliberately one
   function, so this is a one-line change and not a sweep of six backends.
2. A future PRS_TPSP release adds one. Same one-line change.

**Deferred because.** Inventing a wire code with no spec or profile behind it would make this
UTM's responses non-conformant for the sake of a distinction ranked below the E_IIF / E_NTF
split that was actually asked for. See also the `Unsupported` → E_NTF reading documented at
`ridFromOpStatus`: that is a spec reading rather than a spec quotation, and it carries the
same "change it here, once" property should a narrower reading of PRS_TPSP §6.8 later prevail.

**Done when:** the `NotPermitted` arm of `ridFromOpStatus` answers a Result ID other than
E_NOK. That requires a PRS_TPSP release or an owning OEM profile to define a privilege code
first, so no change confined to this repository can close this entry — which is why it stands
in `tools/debt_accepted.txt`.

---

## TD-17 — a suite-qualified case id silently loses its per-case DUT vsomeip flavor

**Status:** RESOLVED (2026-09-24). **Logged:** 2026-09-18, from a consumer report of a build
registering an injected suite alongside the in-tree one; verified in-tree at `8fb3c671`. Accepted
until 2026-09-24, when TD-37/TD-38 landed the suite scoping it waited on. The body up to
**Update** is the debt as logged; **Update** and **Resolution** record what changed and what
closed it.

**What it is.** The orchestrator's per-case DUT flavor table
(`dut/env/orchestrator/src/dut_variant.rs`) is built from the harness's
`--list-vsomeip-variants`, whose rows carry BARE case ids — all fifteen of them, none with a
suite separator. `parse` keys the map on that bare id, uppercased. `resolve` is then called from
`dispatch.rs` with the SCHEDULED TOKEN, which may be suite-qualified. A qualified token uppercases
to `TC8:<ID>` and misses a map keyed `<ID>`. On a miss the dispatch falls back to the base vsomeip
config with no `TC8_DUT_*` env, and emits no log line and no error.

So a qualified run of a flavor-needing case executes against a DUT that was never given the second
service, shared port, or second instance the case requires, and nothing in the verdict, the JUnit
row, or the console says so.

**Why it exists.** The harness has three list surfaces and only one of them qualifies.
`--list-cases` prints a non-default suite's prefix verbatim — `dut/env/list-cases-ids.awk`
documents that it captures a bare and a qualified id alike, so qualified ids are first-class,
documented input. `--list-vsomeip-variants` and `--list-neg-rows` emit bare first fields. The
orchestrator keys all three tables on a token that may or may not be qualified, and nothing
reconciles the two spellings. A single-suite build never needs qualification (an unqualified id is
unambiguous), so CI has never reached the mismatch.

**Risk if left.** Bounded today, sharp the moment a second suite is registered. Of the three
tables the orchestrator builds this way, only one degrades silently:

- `list_secondary_iface_cases` — safe by construction; both sides come from `--list-cases`.
- `list_negative_rows` — would panic rather than degrade; `worker.rs` expects the schedule to
  carry every scheduled case, and main builds that schedule from the same bare list.
- `dut_variant` — silent, and it is the PROVISIONING axis. An expectation override changes what
  the tester expects; this changes what the DUT is running.

**Textbook fix.** Discriminate on whether STRIPPING the suite would have hit the table.
"Qualified and missed, therefore error" is the wrong rule — once suites are scoped, every injected
case legitimately misses:

- suite is the default — strip and look up. Correct resolution, not a workaround: the table IS the
  default suite's table.
- suite is not the default and the bare part WOULD hit — refuse loudly. A flavor must never travel
  to another catalog by id coincidence.
- suite is not the default and the bare part misses — legitimately no flavor.

**Deferred because.** No build the project ships can reach it: the in-tree suite is the only one
registered, and an unqualified id resolves unambiguously. The third branch above only acquires
meaning once injected suites exist, and the shape of suite scoping is still being decided. A
consumer's request to let an injected suite alias an in-tree case is settled in shape and mechanism
(a pointer file in the injected case directory, resolved at run time) but stays a DRAFT marked "do
not implement": its deciding number, how many catalog entries an alias would save, needs a spec
volume the consumer holds and this repository does not. Implementing against a scoping model that
has not landed would most likely be redone. One adjacent gap belongs with it when that work starts:
the orchestrator has no `--inventory-overrides` passthrough at all — the flag exists on the harness
CLI, but the orchestrator's only mentions of it are comments, so a consumer driving runs through
`tc8-orchestrator` always gets the in-tree overrides file.

**Done when:** `dut_variant::resolve` discriminates the three branches above, a test proves the
middle one refuses rather than falling back, and the orchestrator gains an `--inventory-overrides`
passthrough. Both halves wait on the suite-scoping model leaving DRAFT, which is a decision this
repository does not own — hence the entry's place in `tools/debt_accepted.txt`.

**Update (2026-09-24).** The harness side of suite scoping landed with TD-37/TD-38. So the
acceptance argument, that implementing now would most likely be redone, no longer holds, and
the id has left `tools/debt_accepted.txt`. The consumer's alias DRAFT is not needed to close this:
if it lands, it adds a resolution (an explicit pointer to another catalog's case). It does not redo
one. One fact above changed. `--list-vsomeip-variants` and `--list-neg-rows` now print a non-default
suite's rows as `suite:ID`, each resolved from that suite's own catalog. So an injected suite CAN
now carry a flavor of its own, and the rule gains one case ahead of the middle branch: an
exact own-suite row wins.

**Resolution.** `dut_variant::lookup` (`dut/env/orchestrator/src/dut_variant.rs`) implements the
rule in this order:

- A bare token, or one qualified with the default suite, resolves the in-tree row. A bare token IS
  an in-tree case, since the listing qualifies every other suite's.
- A non-default token resolves that suite's own row when there is one.
- A non-default token with no row of its own whose bare id holds an in-tree flavor is REFUSED.
  `resolve` returns an error, which the worker reports as `error:dispatch_fault`. It is resolved
  before any conditioning or spawn, so a refused case leaves nothing behind.
- Otherwise the token gets no flavor.

The orchestrator's reading of the `suite:ID` grammar lives in one module,
`dut/env/orchestrator/src/case_token.rs`. Its `DEFAULT_SUITE` is pinned by a test to `kDefaultSuite`
in `case_suite.h`, as `src/harness/CMakeLists.txt` derives its own copy. The `--inventory-overrides`
passthrough exists. The flag is checked for a real file and made absolute in `main.rs`, and
`Config::inventory_args` is the one place its arguments are built. `Config::harness_test` starts all
three listing calls, and the per-case run takes the same arguments, so the flavor table, the
negative rows, the secondary-iface set and each case's own axes all read one file. Proven by
`cargo test` in `dut/env/orchestrator`: 85 passed. Among them,
`another_suite_refuses_rather_than_inherit_the_in_tree_flavor` shows the middle branch refuses
rather than falling back. The refusal has one gap that no row can close yet, registered as TD-39.

---

## TD-18 — a cold neighbour-cache premise is arranged but never verified at window open

**Status:** OPEN (accepted). **Logged:** 2026-09-19, from a §4.5 false-observation caught this
session while adopting the Tier-2 seam.

**What it is.** Several §4.2 and §4.5 cases are written against a DUT whose neighbour cache does
NOT hold an entry for the tester: the behaviour they grade is the resolution the DUT is forced to
perform. The orchestrator arranges that premise — every case's conditioning list begins with a
`NeighFlush { side: Dut }`, which applies as `ip -n <ns> neigh flush dev <iface>` and has no
restore step. Nothing then verifies it. There is no read-back of the DUT's neighbour table at any
point, and specifically none at the moment the listen window opens; the orchestrator's only
`neigh show` resolves the DUT MAC on the TESTER side during bring-up and is unrelated.

So the premise holds at conditioning time and is assumed to still hold some seconds later. Between
those two moments the harness does its own work — a readiness probe, a control-channel round trip,
a capability query — and any of it can make the DUT resolve the tester and re-warm the entry the
case needs absent.

**Why it exists.** The flush is a bring-up step, written when conditioning was the only thing that
touched the DUT between cases. The Tier-2 DUT-control seam added a second population of traffic in
that same gap, and it grew case by case rather than arriving as one change that would have prompted
the question.

**Risk if left.** Both verdict directions, silently. A re-warmed entry means the DUT emits no ARP,
so a case asserting the request FAILS a conforming DUT; and a case asserting an ABSENCE passes
without its premise ever having been true. Measured this session: declaring a capability on eleven
§4.5 link-local cases opened the capability gate, whose `OpQueryCapabilities` probe made the DUT
ARP for the probe's source, and that ARP landed inside the §4.5 capture window where the SCXML read
it as the DUT's own link-local Probe. The fix shipped for that — answering backend-static
capabilities without touching the DUT (`IDutControl::staticCapabilities`) — removes ONE source of
re-warming traffic. It is not a guard on the premise, and the next source added will not announce
itself either.

**Textbook fix.** Read the DUT's neighbour entry for the tester back at window open and treat a
violated premise as a non-conclusion, not a verdict. The disposition channel already exists and is
exactly the right one: `tc8::UnperformedStimulus` forces `inconclusive` for a stimulus that could
not be performed, over both pass and fail, and leaves `Error` alone (see TD-notes in
`src/cli/commands/test_command.cpp` and the unperformed-stimulus guard). "The premise was not in
force" is the same class of statement as "the stimulus did not happen": neither is a claim about
the DUT.

**Deferred because.** The read-back is topology-dependent and only one topology can do it today.
`single-pc` netns can query the DUT namespace directly; `external` and `ssh-remote` need DUT-side
access the harness does not have in general; `lwip-tap` has no shell at all, and its embedded stack
would have to answer over the control seam — which means a new Tier-2 primitive (query a neighbour
entry) rather than a shell command, and that belongs with the seam's own design rather than bolted
on beside it. Shipping the netns-only half first would be worse than shipping nothing: the other
three topologies would report the same clean verdicts they do now, and their silence would become
indistinguishable from a verified premise — which is the precise failure this entry exists to
describe.

**Done when:** every topology the harness ships can read the DUT's neighbour entry for the tester
back at window open, and a violated premise routes through `tc8::UnperformedStimulus`. Partial
coverage does not close it, per the paragraph above. `lwip-tap` needs a Tier-2 neighbour-query
primitive designed with the seam, and `external` / `ssh-remote` need DUT-side access the harness
does not have in general — neither is reachable from this repository alone, which is why the
entry stands in `tools/debt_accepted.txt`.

---

## TD-19 — TCP cases drove the DUT over the seam without declaring kCapTcpControl

**Status:** RESOLVED (2026-09-19, same day). **Logged:** 2026-09-19, from a seam-capability audit
run after the ARP instance of the same gap was fixed.

**Resolution.** 166 of 181 `tcp_*.h` cases reach `ITcpControl`; all 166 now declare
`kCapTcpControl`, via three new sibling bases in `_tcp_traits_base.h` — `TcpDutDrivenBase`,
`TcpEgressFaultNegDrivenBase`, `TcpIngressFaultNegDrivenBase` — with 135 case headers repointed
onto them. The 15 that do not reach the seam are unchanged and still declare nothing, so no case
is skipped for a sub-interface it never touches. Verified both directions by audit (166/166
declare, 0 non-driver over-declares) and on the wire: 168 runnable TCP cases, 112 PASS / 56 SKIP
before and after, ZERO verdict diff.

⚠ One half is NOT proven and should not be claimed: no shipped backend LACKS `kCapTcpControl`
(opcode and AUTOSAR-testability both advertise it), so nobody has observed these declarations
actually producing a skip. The gate mechanism itself was proven end to end the same day on the
ARP set — `skip:requires_capability_0x8_unavailable_on_autosar-testability` for the declaring
cases and normal runs for the rest — so what is unproven here is these particular declarations
firing, not the machinery.

★ **The registered count was wrong twice, and the corrections are the useful part.** It was filed
as 53. The instrument missed `seamTcpControl(dut)`, the canonical accessor wrapper, because the
sweep excluded `dut_control.h` where it is defined (53 -> 91); then it missed helpers that reach
the seam TRANSITIVELY, such as `driveSeamSynSentOpen` -> `seamConnectTcp` (91 -> 166). The second
correction surfaced only because the over-declaration check flagged seven cases as declaring
without using — files the fix had never touched. They were using it; the detector could not see
how. A sweep that checks only the direction it expects to find would have shipped 91 and called
it complete.

**What it is.** A case that drives the DUT through an `IDutControl` sub-interface is only
measurable on a backend that provides it, and says so with `kRequiredCapabilities` so the gate
can decline a backend that does not. An audit over all 749 case headers — resolving seam
helpers to accessors transitively, walking base chains on the declared side, and reading
COMMENT-STRIPPED source — found cases declaring less than they call. All of them omit
`kCapTcpControl`, which BOTH shipped backends advertise, so the gate is satisfied, the cases
run, and nothing is misreported today. (The count went 53 -> 91 -> 166 as the instrument was
corrected; see the Resolution note above. Figures below that say 53 are the as-filed numbers and
are left as written rather than back-edited — the count moving is part of the record.)

⚠ The instrument had to be corrected twice before that number meant anything, and the earlier
figures are in this file's history, not its text. Scanning `dut_control.h` made every interface
method look like a seam helper, which put `kCapTcpRecvOob` on nearly every TCP case; scanning
comments then credited `tcpStateProbe()` — mentioned once, in prose, in `tcp_pilot_common.h` —
to ten cases that never call it. Both times the tell was the same: the answer was too uniform to
be true. Four cases the audit could not see at all (no base clause, no declaration) were found
by a reviewer, not by the sweep, and fixed alongside it.

The `tcpStateProbe` half of that is worth stating as a RESULT rather than only as a
mis-measurement, because it is the one part of this model that has been confirmed end to end on
a backend that declines: on an AUTOSAR-testability run of 494 cases, the cases that skipped for
the state-probe bit were exactly the ten that call `tcpStateProbe()` — `TCP_BASICS_02/07/17`,
`TCP_FLAGS_PROCESSING_11`, `TCP_RETRANSMISSION_TO_03/04/05/06/08/09` — and the ten that do not
call it ran and passed. Both halves right, with no change needed. That is the standard the 53
below should be held to, and it is also why the near-miss mattered: adding the bit to the wrong
ten would have turned ten sound passes into skips.

**Why it exists.** The TCP cases predate the Tier-2 seam and reach `dut.tcpControl()` directly
from their stimulus bodies. The seam adoption work declared capabilities on the domains it
migrated; TCP was already calling the accessor and so never looked like a migration.

**Risk if left.** Latent and bounded, but "latent" is a property of today's backends rather than
of the code: it holds only while every backend in play advertises the bit. The moment one
without `ITcpControl` is added, all 53 stop being declined, and how they then fail is NOT
uniform. Where the un-taken seam call is the stimulus, the case reports
`no_dut_*_within_listen_window` — loud, and investigated; that is what 33 ARP cases did on the
testability backend. Where the un-taken call only sets up or tears down, the case is graded on
wire evidence alone and reports a clean PASS whose premise was never established. A
non-conclusion gets looked at; a green does not. Neither was visible in CI, which runs
`--dut-control=opcode`, the backend that has everything.

The silent form has a worst case, and it is not hypothetical. Where the seam call is what
ESTABLISHES a case's premise and the case can reach a `pass` final without observing anything,
an unprovoked listen window IS the pass condition: nothing happens, the deadline expires, and
the case reports PASS on a premise nobody established. MEASURED on an AUTOSAR-testability run:
ARP_03 and ARP_05 were passing that way, and declaring `kCapArpConditioning` converted both into
honest skips. Two vacuous greens, invisible from any lane where the provocation works, because
there the premise is real and the pass is sound.

**The checkable predicate is narrower than "the case grades an absence", and narrower than "the
SCXML has a `deadline_exceeded` transition targeting `pass`".** It is: *a `pass` final is
reachable from the INITIAL state by timeout transitions alone.* The middle formulation is
necessary but not sufficient and would mislead — IPv4_AUTOCONF_INTRO_01 has such a transition,
but it sits in the THIRD state, behind an observed DISCOVER and an observed REQUEST. Its
initial-state deadline lands on `inconclusive_no_discover`, so an unprovoked run there is a
non-conclusion someone investigates. Confirmed on the same testability run: INTRO_01 reported
inconclusive, not pass, while ARP_03/_05 reported pass. An absence case that routes its first
deadline to an inconclusive final protects itself however broken the provocation is.

Swept on that predicate, the population is 24 cases: ARP_03, ARP_05, ARP_21/27/37/42 and
TCP_CLOSING_13 directly, plus the 17 that reach it through
`_templates/icmpv4_negative_absence` or `_templates/ipv4_negative_absence`. Of the 24, exactly
two establish their premise over the seam — ARP_03 and ARP_05 — and both now declare. The other
22 are tester-provoked (`emitArpFromTester`, `emitTcpFrame`) and touch no sub-interface, so no
backend can take their premise away. None of the 53 below is in the population at all. TD-19 is
therefore a latency problem and not a live false-PASS one — but that is a fact about today's 53,
and any new case that can reach `pass` on a timeout must declare what establishes its premise
before it is written.

**Fix as applied.** The same axis split the ARP fix used, not a base-wide declaration. Driving the
DUT is INDEPENDENT of dispatch shape: `TcpAnyBase` carries 109 cases and 81 reach the seam, so
declaring on the base would capability-skip 28 observation-only cases for a sub-interface they
never touch — trading one wrong non-conclusion for another. The `TcpDutDrivenBase` sibling and its
two fault-flavoured variants carry the declaration instead, mirroring `ArpDutProvokedBase`.

⚠ A mid-course measurement briefly said 106 of 109 drive, which would have argued for declaring on
the shared base and marking exceptions. That figure came from an ad-hoc regex matching any
`driveSeam*`, including seams that are not TCP. Re-measured with the same detector as the rest of
the audit it is 81, and the axis split stands. Two instruments, two answers, and the design
decision hung on which one was believed.

**Why it was not deferred after all.** It was filed as deferred on the grounds that it changes no
verdict on either backend today — and that is exactly the reasoning the risk section above calls
the weakest available. The work is a header-only change whose whole value is that it must not
change a verdict, which is cheap to prove and worth nothing unproven, so it got its own
before/after over the full runnable TCP set rather than riding along with something else.

The runtime guard from the ARP pass stays as the backstop for whatever this audit could not see:
the seam-absence branches record a named unperformed stimulus (`dut_arp_control_absent` and
siblings), so a case reaching a missing sub-interface reports that name instead of inventing a
DUT fault. TCP is the exception worth knowing about — `seamTcpControl` ASSERTS rather than
recording, so there the backstop is an abort in a debug build and undefined behaviour under
NDEBUG. That is the strongest argument for the declaration and the reason this did not stay open.

---

## TD-20 — the UT-Confirmation field check cannot tell "the DUT reported no receipt" from "no Confirmation arrived"

**Status:** RESOLVED (2026-09-23). **Logged:** 2026-09-23, reading
`tests/_templates/udp_ut_received_check.sce-template.xml` while auditing negative controls.
The entry below is the debt as logged; **Resolution** at its end records what closed it.

**What it is.** The template's `listening` state has exactly two `udp_observed` transitions and
both conjunct `captured.ut_received == 1`:

| Confirmation | what it means | where it lands today |
|---|---|---|
| arrives, `ut_received == 1`, predicate true | the DUT received it, fields agree | `pass` |
| arrives, `ut_received == 1`, predicate false | the DUT received it, a field disagrees | `fail_field_mismatch` |
| arrives, `ut_received == 0` | the DUT says it did NOT receive it | no transition matches |
| never arrives | the observation vehicle failed | no transition matches |

The last two rows share one outcome: the deadline fires and the run reports
`inconclusive_no_ut_confirmation`. For the third row that reason is not merely coarse, it is
FALSE — a Confirmation did arrive, and it carried the DUT's answer.

**Why it exists.** The template's own header documents a three-state model (pass /
field-mismatch / no-confirmation) and the `ut_received == 1` conjunct is what makes the
middle state mean "received but wrong". It reads as a soundness guard, and against the
observation-vehicle failure it is one. The fourth state — "received nothing, and said so" —
is a DUT answer rather than a vehicle failure, and it was never given a state of its own.

**Risk if left.** A conforming-DUT regression is downgraded to a non-conclusion, and
non-conclusions render as JUnit `<skipped>`, which is green. Nine case directories consume
the template (`git grep -l udp_ut_received_check -- tests`), five positive and four `_NEG`.
The positive direction is the sharp one: these cases inject a datagram the DUT is REQUIRED to
receive, so `ut_received == 0` is an observed violation and belongs on `fail`. For the `_NEG`
direction the same collapse costs less but still misreports — a fault that made the DUT drop
the datagram outright is indistinguishable from an lwIP fixture that never answered.

**Textbook fix.** A fourth transition, ahead of the deadline: `has_ut_response and ut_opcode
== 0x81 and ut_status == 0 and ut_received == 0` to a `fail` final whose reason names the
report (`dut_reported_no_receipt`), leaving the deadline to mean only what it says. The
verdict-model vocabulary already has the shape — this is the same pass/fail/inconclusive split
the template's header argues for, with the missing fourth row filled in rather than a new
concept introduced.

**Why it was not fixed with the sighting.** It was found while the lwIP fixture was dropping
fragments before the IP layer (see `dut/lwip_dut/lwipopts.h`, `MEMP_NUM_TCPIP_MSG_INPKT`),
which made the DUT genuinely fail to receive datagrams it should have received. Landing the
fourth transition then would have turned a fixture defect into a batch of DUT FAILs and buried
the real cause. That fixture defect is now fixed, so the ordering constraint is discharged.

**Done when:** the template carries a transition for `ut_received == 0` landing on a `fail`
final with its own reason, the `_NEG` variants' flavour of it is settled the same way, and a
full run of the nine consuming cases on both DUT backends shows no verdict change on a
conforming DUT.

**Resolution.** The template now carries a transition for a Confirmation with
`ut_received == 0`, placed ahead of the deadline. It lands on a final whose reason is
`dut_reported_no_receipt`. The deadline keeps its guard-free form, so it still means only
"no Confirmation arrived". The new final's state, verdict and role are bound per consumer,
and only two bindings are coherent:

- **Positives** (UDP_FIELDS_12, UDP_USER_INTERFACE_02/03/04) bind `fail_no_receipt` /
  `fail` / `observed_violation`. The sibling `ipv4_udp_ut_presence` template already treated
  a wrong receipt report as `fail`, so this is not a new policy.
- **Report-fault `_NEG`s** bind `inconclusive_no_receipt` / `inconclusive` /
  `precondition_unmet`. Their fault corrupts a field of a datagram that was *received*, so a
  report of no receipt means the fault had nothing to act on. That is neither the fault
  demonstrated nor the fault inert. `negative_coverage_audit.py` also allows a `_neg` exactly
  one fail final (its `fail_compliant` branch).

The positives now have two fail finals each, so Phase F needs a `_neg` proving the new one
can be reached. A new app-fault flavour, `kAppFaultReportNoReceipt`, makes the data listener
lose a datagram it received. The new cases UDP_FIELDS_12_NEG2 and UDP_USER_INTERFACE_02/03/04_NEG2
arm it and pass only on `received=0`. They are registered in `tools/fault_injection_coverage.json`
and in the lwIP smoke list.

The consumer count in this entry was wrong. `git grep -l udp_ut_received_check -- tests` lists
nine paths, but one is the template itself and `udp_user_interface_01` only names the template
in a comment. The real count is **eight**: four positives and four `_NEG`s.

Measured on 2026-09-23 with the built harness and lwIP DUT:

- **lwip-tap:** all 12 cases (the 8 consumers plus the 4 new `_NEG2`s) PASS, with 0 failures,
  0 skips and 0 non-conclusions. Each `_NEG2` pass was a 12-byte Confirmation (`received=0`);
  each positive and `_NEG` pass was a 28-byte one (`received=1`).
- **single-pc** reference DUT: the 4 positives PASS. The 8 `_NEG`/`_NEG2` cases skip on
  `kCapAppFault` (`0x200`), which the reference DUT does not advertise.

No verdict changed on a conforming DUT. `negative_coverage_audit.py --check` and
`verdict_drift_audit.py` are green, and FAULT_INJECTION stays at 177.

---

## TD-21 — the link-local helper reads the DUT's address by raw opcode, with no seam operation behind it

**Status:** RESOLVED (2026-09-25). **Logged:** 2026-09-23, re-measuring Tier-2 seam adoption at
HEAD.

**How it was repaid.** `ILinkLocalControl::queryCommittedAddress` answers the DUT's committed
address as a `net::OpStatus` plus the value, the opcode backend implements it over the existing
OpQueryLLAddress round-trip, and `ipv4_linklocal_common.h` asks through `IDutControl` instead of
building the frame and opening a socket of its own. The two scheduling helpers take the seam and
capture it by pointer; the twelve §4.5.6.2 call sites already held an `IDutControl&`.

`OpStatus` rather than a bool because the three ways this fails are different things: a backend
whose protocol has no such read (`Unsupported`, the decline the gate turns into a skip), a
transport or malformed-reply failure (`Failed`), and success. The helper it replaced collapsed
all three into `0`. The operation is pure virtual deliberately — a default `Unsupported` would
let a new backend inherit a silent decline, and a silent decline of a READ is indistinguishable
from a DUT that has not committed yet.

**Verified by running, not by compiling** — and the run is what caught the mistake. The first
implementation declined whenever a raw transport was configured, reasoning that such a backend
could not answer. `dut/../dut_control_factory.cpp` sets `raw.iface` on EVERY opcode backend, so
the branch was always taken and all twelve cases turned into non-conclusions: compiled clean,
Done-when satisfied, wrong. Raw injection is a per-OPERATION choice here — it exists for
requests that must not provoke a tester-side ARP before the DUT has an address to answer
from — and a read has the opposite precondition. The read is now kernel-routed unconditionally,
as the helper it replaced always was, and all twelve pass.

**What it is.** `src/sce_integration/include/sce_integration/ipv4_linklocal_common.h` reaches
the Upper Tester through `IDutControl` everywhere but one call: it builds a
`buildQueryLLAddressRequest` frame itself and sends it. No case header still constructs a UT
request directly — `git grep -lE 'build[A-Z][A-Za-z]*Request\(' -- src/sce_integration/include/sce_integration/cases`
answers zero — so this single site is what is left of the opcode-hardwired path, and sixty
case headers include the helper that holds it.

**Why it exists.** The seam's link-local sub-interface was designed around the operations that
CHANGE the DUT (start, abort, arm a buggy autoconf). Reading a value back is a different shape,
and the one call that needed it was already written against the opcode client, so it stayed.

**Risk if left.** Two things, both quiet. A backend that is not the opcode DUT cannot answer
this call at all, and because it bypasses `IDutControl` it also bypasses the capability gate:
a case reaching it on such a backend gets a timeout rather than an honest capability skip.
And it is the counter-example that weakens the seam's invariant — "every DUT interaction goes
through `IDutControl`" is either true or it is a convention, and one exception makes it the
latter.

**Textbook fix.** Give `ILinkLocalControl` a read operation that answers the DUT's current
link-local address (an `OpStatus` plus the address, matching the vocabulary
`include/tc8/net/op_status.h` established for the capability operations), implement it on the
opcode backend over the existing 0x0E query, and leave a backend that cannot answer to decline
so the gate can skip.

**Done when:** `git grep -E 'build[A-Z][A-Za-z]*Request\(' -- src/sce_integration/include/sce_integration`
matches nothing outside `dut_control.h` itself, and the sixty consuming cases run unchanged on
the opcode DUT.

---

## TD-22 — nothing proves a declared capability bit is ever demanded, or an advertised one ever reachable

**Status:** RESOLVED (2026-09-25). **Logged:** 2026-09-23, after two capability-declaration
passes (TD-19 and the ARP pass before it) each found the gap by hand.

**How it was repaid.** `tools/capability_gate_audit.py` joins the three sides, carries an
18-check `--self-test`, gates `pre-commit` and `build-test.yml`, and is green with two ratchet
lines, both argued in `tools/capability_gate_reserved.txt`.

**Six real findings, all of the dangerous direction**, and all fixed:
`TCP_FLAGS_INVALID_03_NEG/_04_NEG/_05_NEG/_05_NEG2`, `TCP_FLAGS_PROCESSING_08_NEG3` and
`TCP_SEQUENCE_02_NEG` call `driveSeamSynSentOpen` — a non-establishing active open left in
SYN-SENT, its own sub-interface — while declaring only what their base declares. Two of the six
reach it through a shared `_neg_common` helper, so a direct grep would not have found them.
Declared per-case rather than by widening the base (1 of that base's 15 users needs it, 3 of
another's 38) and written as `Base<SM>::kRequiredCapabilities | …` so the two cannot drift. All
six still pass on lwip-tap.

**Three of the four defects were the AUDIT's**, which is why its first output could not be
believed:

| defect | findings it invented |
|---|---|
| a capability passed as a TEMPLATE ARGUMENT (`ArpFaultNegUdpBase<SM, kCapIngressFault>`) was invisible — the base's body holds the PARAMETER name | 41 false UNDECLARED, masking the 6 real ones |
| a derived declaration was UNIONED with its base's, where C++ SHADOWS | 8 false OVERDECLARED |
| a helper with a brace-initialised default (`const Cfg& c = {}`) was invisible, and with it the whole DHCP demand chain | 95 false OVERDECLARED |

⚠ **Two attempted fixes were worse than the defect, and only counting caught them.** Feeding
every `cases/*.h` into the helper table merged ~800 `stimulus` bodies under one key — bodies are
keyed by function NAME — and made every case appear to demand every bit: 6 findings became
9653. Requiring an `inline`/`template` prefix on a definition dropped the count to 2, which
looked like success and was blindness: it lost 66 real helpers, including the member functions
that ARE the seam accessors. The rule that holds is narrower and principled — a definition's
name is not immediately preceded by `::`, so `std::chrono::milliseconds(400),` spanning into a
later brace stops matching as a function whose "body" is a fragment of the enclosing lambda.

⚠ Also corrected here: an earlier note in this entry read the census line "traits structs
resolved: 41" as 41 of 806 CASES resolving. 41 is the number of traits BASES; cases are resolved
per file. The real causes are the three above.

**What it is.** `src/sce_integration/include/sce_integration/dut_capabilities.h` defines
thirteen bits. Three independent things must agree for one to mean anything: a case declares it
in `kRequiredCapabilities`, a backend advertises it, and some code path actually demands the
sub-interface the bit stands for. Nothing checks that they do. Every combination of two out of
three fails silently:

- declared but never demanded — the case skips on a backend that could have run it.
- demanded but never declared — the case drives a sub-interface the gate never checked for;
  on the TCP seam that is an assert in a debug build and undefined behaviour under NDEBUG.
- advertised but never demanded — the bit is decoration, and a backend that starts declining
  it changes nothing, so the decline is untestable.

**Why it exists.** The three sides were built at different times and each is individually
readable. The audit that would join them is a whole-tree question — which case headers reach
which seam accessor, transitively through the pilot helpers — and both passes that asked it
asked it with an ad-hoc regex.

**Risk if left.** Measured, not speculative. Both hand passes produced wrong numbers before
they produced right ones: one credited ten cases with a capability because the detector read a
mention in a COMMENT, which on a declining backend would have turned ten sound passes into
skips; another missed every case reaching the seam through a helper because it had no
transitive closure, and undercounted by nearly half. A gate would have caught both the moment
they were written; a reviewer caught one of them and the over-declaration check caught the
other, which is not a mechanism.

**Textbook fix.** An audit in the existing family (`tools/negative_coverage_audit.py`,
`tools/workflow_runner_audit.py`): resolve each case header's declared set, resolve the seam
accessors it reaches through the include graph, and require the two to agree; separately
require every defined bit to be advertised by at least one backend and demanded by at least
one call site, with an explicit ratchet line for a bit deliberately reserved ahead of its
backend. Fail closed — a header the audit cannot resolve is a finding, not a pass.

**Done when:** `tools/` holds that audit with a `--self-test` proving each direction fires, it
resolves a capability inherited from a base and one passed as a template argument (both shapes
are live in the tree), it gates `pre-commit` and `build-test.yml`, and it is green with no
ratchet entries beyond the ones argued in the file itself.

**Half landed, 2026-09-24.** `tools/capability_gate_audit.py` exists, self-tests pass (13
checks), and it runs whole-tree. It is NOT yet wired into `pre-commit` or `build-test.yml`,
because it currently reports 159 findings and a gate that reds every commit is not a gate.
Wiring it is the remaining half, and it waits on those findings being triaged rather than on
more tool.

What it reports, and why the numbers are worth keeping: each blind spot of the AUDIT was found
by disbelieving its own output, and each fix changed the count sharply.

| the gate could not see | it wrongly reported | after the fix |
|---|---|---|
| a case specialises `TestCaseTraits<SM>`, so the name carries a template argument | 780 UNRESOLVED | 190 |
| a ROOT traits base has no parent, so `struct X {` never matched | 51 false UNDECLARED | 30 |
| a base file holds FREE FUNCTIONS beside its structs (`dut.arpControl()` lives in one) | 33 ARP + 20 TCP false OVERDECLARED | 0 |

What survives is a genuine finding of the class this entry describes: 95 cases inherit
`Dhcpv4AnyBase`, which declares `kCapDhcpClientControl`, while never calling
`emitStartDhcpClient` — the 86 cases that do call it are a different set. Those 95 would SKIP
on a backend that declines the bit, even though nothing in them needs it. 29 more do the same
with `kCapUdpReceiveControl`. That is the same shape as the ARP pass measured by hand
(28 cases declared, 11 drove), now found by a machine instead of a reviewer.

⚠ The audit resolves demand by NAME, not by a compiler's call graph — its own docstring says
so, and the table it resolves against is the thing to review when a seam operation is added.
Three of its four blind spots above were of exactly that kind, so treat a zero from it as
"nothing this table can see" rather than "nothing".

---

## TD-23 — an excluded case is never observed again, so both exclusion ledgers can only rot

**Status:** RESOLVED (2026-09-25) against the Done-when below; the `_NEG` half of the
original observation outlived it and is now docs/tech-debt.md TD-47. **Logged:** 2026-09-23.

**How it was repaid.** All three Done-when clauses, in the order they are stated.

*Justifications in-tree*: `tools/debt_census.py` reports zero known-fail entries whose
justification does not resolve in-tree — the in-tree pointer gate closed that while TD-34/36
were repaid.

*The excluded set is re-measured, and has been seen to red*: `platform_known_fail_verdict`
records the `class:reason` each registered deviation actually lands,
`tc8-harness test --list-known-fails` prints the pairs, and `tc8-orchestrator --known-fail`
runs exactly the excluded set with NOTHING injected and asserts them. Both lanes carry the
stage — `.github/workflows/lwip-sweep.yml` for the fixture, `.github/workflows/smoke-test.yml`
for the reference DUT — and neither adds a cron, which this entry argued against: the smoke
stage is per-push and the set is small and disjoint from the lanes above it, which is what
makes measuring it affordable where measuring everything was not.

The red was DEMONSTRATED rather than assumed, on 2026-09-25: a copy of the lwIP overrides with
`ARP_05`'s verdict altered to one the DUT no longer lands produced
`FAIL ARP_05 — expected 'fail:a_reason_the_dut_no_longer_lands', harness returned
'fail:dut_arp_request_after_gratuitous_learning'` and exit 1. The message names both verdicts,
so the reader is told whether the platform was fixed or its defect changed shape.

*A mark must name what it suppresses*: `negative_coverage_audit.py` rejects a verdict that is
not a `class:reason` token (KNOWN_FAIL_MALFORMED), one naming a final the case does not have
(KNOWN_FAIL_STALE), one on a case with no fail final at all (KNOWN_FAIL_NO_FAIL_FINAL) and one
on something that is not a positive case (KNOWN_FAIL_NOT_POSITIVE). The category error this
entry recorded — a mark suppressing an INCONCLUSIVE while claiming to suppress a FAIL — is now
unstateable: the verdict carries its class.

**The measurement that closed it.** Twenty-one registered deviations across both platforms, all
re-run on 2026-09-25. lwIP: nine `fail:`, seven `inconclusive:`, none passing. Linux reference:
four `fail:`, one `inconclusive:`. Every prose reason that already named a verdict agreed with
the measurement, so nothing was stale at the moment the mechanism landed — that is the baseline
it now holds rather than a claim that staleness never happened.

**What it is.** Two ledgers withhold cases from a verdict: `platform_known_fail` in the
`inventory_overrides.json` files (a DUT is known to fail the case) and, in the other direction,
`tools/fault_injection_floor.txt` plus the `_NEG` pairings that record a fault as empirically
proven to fire. Both are written from a measurement taken on the day. Neither is re-measured:
a known-fail case is EXCLUDED FROM THE RUN, so the run cannot notice it has started passing,
and a `_NEG` whose fault has gone inert reports a non-conclusion, which renders as JUnit
`<skipped>` and is green.

**Why it exists.** Exclusion is the correct immediate response to a case that cannot pass on a
given DUT — it keeps the gate honest about the rest. The cost is that exclusion and observation
are the same switch.

**Risk if left.** Measured once already: a refresh of the known-fail ledger found entries that
had begun passing, and a separate check found a ledger mark suppressing an INCONCLUSIVE rather
than a FAIL — a category error the mark itself could not express, because the case has no
`fail` final at all. Each stale entry is a case the suite silently stopped grading. Nine of the
Linux-side entries additionally justify themselves by pointing at paths outside this repository
(`tools/debt_census.py` lists them), so a reader here cannot check the reason either.

**Textbook fix.** Three parts, independent. Make the exclusion OBSERVABLE: run the known-fail
set — the complement of what `dut/lwip_dut/sweep-cases.sh` emits, since that script passes
`--exclude-platform-known-fail` — and report "these are still failing", reddening only when one
has started passing, which is the signal the ledger exists to catch. Note what NOT to do: a
weekly cron over the whole sweep already existed and was retired on 2026-06-11 because the
serialized self-hosted runner paid about thirty minutes a week for axes already covered
per-push (`.github/workflows/lwip-sweep.yml` records the reasoning). Re-adding that cron would
undo a decision already taken. The excluded set is small and disjoint from the sweep, which is
what makes measuring it affordable where measuring everything was not.
Move every justification in-tree, so `platform_known_fail_ref` resolves to a tracked path or a
TD id. And require a mark to name what it suppresses, so a case with no `fail` final cannot be
marked known-fail at all.

**Done when:** `tools/debt_census.py` reports zero known-fail entries whose justification does
not resolve in-tree, a scheduled run re-measures the excluded set and has been seen to red on a
case that started passing, and a case without a `fail` final is rejected as a known-fail mark.

---

## TD-24 — a multi-phase TCP case answers the DUT once, and a conforming retry starves the later phases

**Status:** RESOLVED (2026-09-25), both halves. **Logged:** 2026-09-23, from the pcap of the one
TCP non-conclusion left in the lwIP sweep (346 of 348 pass, zero failures).

**The observability half.** `seamConnectTcp` — the one place every TCP case's active OPEN goes,
shared by `driveSeamActiveOpen` and `driveSeamSynSentOpen` — now records
`UnperformedStimulus::record("tcp_seam_open")` when the open fails. The open IS the stimulus for
everything downstream of it: with no connection the case never asked the DUT the question its
guards grade, so the verdict must say that rather than report the resulting silence as a DUT
absence.

⚠ That header had ALREADY claimed the property in prose — "a failed open does not mis-report
downstream as a DUT 'no SYN / no FIN' timeout" — while only writing a line to stderr, which no
verdict reads. That is the same shape as the teardown above, where a comment asserted a
`shutdown` behaviour one backend did not have. Both read as true and neither was. The claim is
now pinned by `unit_tests/unperformed_stimulus_test.cpp`
(`ASeamOpenThatDoesNotHappenIsRecorded`), so it cannot quietly become a comment again.

**What was fixed (2026-09-25), three diagnoses deep.** The first two were wrong and are kept
below because the shape of the error is the lesson: "the harness answers the retransmission
once" (wrong — answering cannot help, RFC 793 keeps the peer in SYN-SENT), then "the graceful
close is slow" (wrong — swapping in `abortTcp` changed nothing; both verbs reach the same
teardown). The third held: `UpperTesterServer::tearDownSlot` JOINS the slot worker, and that
worker sits inside `SocketBackend::connectBoundedV4`, which was one uninterruptible `select`.
The teardown tried to release it with `shutdown(SHUT_RDWR)` — a POSIX behaviour the shared code
asserted in a COMMENT. True on Linux. False on lwIP, where `lwip_shutdown` acts on an
established netconn and leaves a pending connect to wait out its own retransmissions.

The fix does not make lwIP honour the comment; it removes the dependency. `connectBoundedV4`
now takes a caller-owned `const std::atomic<bool> *cancel`, polls it between short slices, and
abandons the wait when it reads true; the worker is given its slot's `stop`, which teardown
already sets before joining. No stack-specific behaviour is required of any backend, the
parameter carries no default (Core Guidelines C.140, so a backend not yet written cannot
silently omit the obligation), and the Linux backend implements the same slicing although its
kernel would not need it — the obligation belongs to the interface, and a caller must not carry
one teardown path per stack.

Measured on lwip-tap: teardown request to teardown response **3.47 s → 1.4 ms**, phase 2 gets
its window, the crafted segment goes out, and the DUT emits the RST the case grades.
`TCP_UNACCEPTABLE_08` passes on lwip-tap and on the Linux reference; seven other active-connect
TCP cases re-run unchanged.

**What it is.** `TCP_UNACCEPTABLE_08` runs two phases against two port quads. Phase 1 works:
the DUT opens, the harness answers with a SYN+ACK carrying an unacceptable ack, and the DUT
sends the RST the case grades. What happens next is the problem. RFC 793 says a SYN-SENT
connection receiving an unacceptable ack forms a reset AND STAYS IN SYN-SENT, so the DUT
retransmits its SYN — same source port, same sequence number. On the wire, five times over
about 2.85 s. The harness answers none of them: its crafted SYN+ACK is a one-shot. The 2.4 s
listen window therefore expires inside phase 1, and phase 2 emits its SYN a few hundred
microseconds after the window closed, into a tester with nothing listening, so the kernel RSTs
it. The verdict is `inconclusive:no_dut_rst_phase2_ack_with_unacceptable_ack` — which names
the DUT for a window the harness spent.

**Why it exists.** The Linux reference DUT does not retransmit here, so phase 1 finishes in
milliseconds and phase 2 has the whole window. The single-shot answer was sufficient for every
backend the case had ever run against, and the shape only becomes visible on a stack that
implements the SYN-SENT rule literally.

**Risk if left.** It is a non-conclusion, which renders as JUnit `<skipped>` and is green, and
it sits on the one case in the family that grades the phase-2 path at all. More broadly the
shape is not specific to this case: any multi-phase case whose earlier phase leaves the DUT
retrying will squeeze the later ones, and the reason string will keep naming the DUT. Nothing
currently detects "the window closed inside an earlier phase".

⚠ **The causal chain above is WRONG, re-measured on lwip-tap 2026-09-25 from the pcap and the
harness log.** The observation stands — phase 2 never gets its window — but answering the
retransmissions would not fix it, and phase 1 is not slow.

What the wire actually shows (`--log-dir`, one run):

| t (s) | event |
|---|---|
| 47.834 | DUT SYN, phase-1 quad |
| 47.927 | harness crafted SYN+ACK with the unacceptable ack |
| **47.927** | **DUT RST — the emission phase 1 grades, immediate** |
| 48.127 | a UT request goes out |
| 48.58 / 49.58 / 50.58 / 51.58 | DUT SYN retransmits 2..5 |
| **51.588** | **that UT request is answered — it blocked for 3.46 s** |
| 51.589 | phase 2's DUT SYN, long after the window closed |

Phase 1 succeeds in 93 ms. What consumes the window is the UPPER TESTER CHANNEL: a UT call
made while the DUT's SYN-SENT pcb is still retransmitting does not return until the
retransmission cycle ends. The harness log names the casualty directly —
`tcp-pilot: seam SYN-SENT open failed (connectTcp local=49528 remote=23484, backend=opcode-ut)`
— so phase 2's OPEN timed out, the DUT emitted its SYN late anyway, and no crafted segment was
ever sent for phase 2 because the pilot had already given up.

Answering the retransmitted SYNs cannot help: RFC 793 has a SYN-SENT connection receiving an
unacceptable ack form a reset and STAY IN SYN-SENT, so each answer yields another RST and the
pcb keeps retransmitting — and it is the pcb, not the silence, that holds the UT channel.

**Textbook fix, restated.** Two independent halves, and the first one is different from what
this entry first said. Stop a finished phase's socket from holding the UT channel: phase 1's
teardown must not block on a pcb that will retransmit for seconds (an abort rather than a
graceful close, or a teardown that does not serialise with the next phase's open), or the
channel must not serialise one caller behind another — the same surface `src/upper_tester/
ut_server.cpp` and the socket backends under `dut/` already share for slot teardown, where
`OpAbortTcpSocket` (0x09) is the non-graceful counterpart of the close this phase uses. And
make the starvation observable rather than
inferred — a phase that never opened its own window should say so, in the
`tc8::UnperformedStimulus` vocabulary that already exists for "this did not happen", not report
an absence as if the DUT had been asked. That half is unchanged and is what would have named
this correctly the first time.

**Done when:** ~~the harness answers a repeated SYN on a live phase quad~~ (superseded — see
above; answering cannot help and was never the cause) — MET; `TCP_UNACCEPTABLE_08`
passes on both the lwIP fixture and the Linux reference — MET; and a phase whose window never opened
reports that fact instead of a DUT-shaped absence reason — MET, and proven by a test rather
than by the comment that used to stand in for it.

---

## TD-25 — the lwIP fixture has one address, and the case that needs a second one reports as a non-conclusion

**Status:** RESOLVED (2026-09-25). **Logged:** 2026-09-23, the other non-conclusion in
the same sweep. The entry below is the debt as logged, including an audit note that this
resolution REFUTES; **Resolution** at its end records what closed it and where that note
was wrong.

**What it is.** `UDP_USER_INTERFACE_07` proves the DUT honours a caller-specified source
address, which needs the DUT to HAVE a second one: the netns topology supplies the alias
172.16.0.5 via `dut/env/setup-netns.sh`, and the stimulus passes it as the `OpTriggerSendUdp`
source override. The lwIP fixture runs one netif with one address, so the opcode answers
status 0x03 and the unperformed-stimulus guard correctly downgrades the case to
`inconclusive:stimulus_TriggerSendUdp_not_performed`. The guard is doing its job. What is
wrong is upstream of it: `dut/lwip_dut/sweep-cases.sh` says in its own header that it emits
"every case the fixture can meaningfully pass", and this one cannot, so the list and its
contract disagree.

**Why it exists.** The list is derived rather than hand-written — it is `--list-cases` minus
the entries the per-platform overrides ledger drops — which is the right design and is why it
has stayed correct through every other change. This case simply has no ledger entry, and the
premise it needs is one no existing axis names: `requires_secondary_iface` exists in
`docs/spec/inventory_overrides.json` but means a second INTERFACE on the tester side, not a
second address on the DUT.

**Risk if left.** Small but of a kind worth not accumulating: a standing non-conclusion trains
a reader to expect one, and the next non-conclusion to appear beside it gets the same shrug.
The sweep table in `dut/lwip_dut/README.md` also carries it as a permanent footnote for a
condition that is not a stack deviation at all.

**Textbook fix.** Decide which of three it is, and say so in the tree rather than in a habit.
Give the fixture a second address — lwIP can carry a second netif on the same tap, at the cost
of routing complexity the fixture has so far avoided; or declare the premise as a capability,
so the gate skips the case honestly on any DUT lacking it, which generalises past this fixture;
or record it in `dut/lwip_dut/inventory_overrides.json` as an `expected: false` fixture gap
with an in-tree justification, which is the category the sweep list already drops and the
cheapest honest answer. The capability is the one that answers for DUTs not yet written.

⚠ **The capability option costs a FOURTH resolution axis, which this entry did not say and
which is most of its price.** Audited 2026-09-25: `dut_capabilities.h` resolves a bit in one of
three ways, and "this DUT has a second address" fits none of them. It is not
backend-static — both the netns reference DUT and the lwIP fixture speak the SAME opcode
backend, so `staticCapabilities()` cannot tell them apart. It is not DUT-derived either: that
axis is the `OpQueryCapabilities` (0x16) bitmap, which reports which OPCODES a DUT implements,
and an address is not an opcode — the file's own comment calls the per-opcode bit "a 1:1 proxy
for the whole mechanism", which is exactly what a property bit would not be. And the premise is
compiled rather than configured: `UDP_USER_INTERFACE_07` passes `kDutAliasIp4Be`, a constant,
not a config value that could be absent.

So the honest shapes are: make the premise CONFIGURED (the topology supplies the DUT alias or
leaves it zero) and add a config-derived capability axis alongside the three; or extend 0x16 to
carry DUT PROPERTIES beside opcodes. Both are real protocol or architecture work, and a
half-done version leaves the capability system with an undocumented fourth kind — worse than
either clean answer. The `expected: false` entry remains available and correct, and remains
per-platform bookkeeping rather than something a DUT not yet written can decline.

**Done when:** a run of the lwIP sweep reports zero non-conclusions for this case — because it
passes, because the gate skipped it on a declared capability, or because the ledger no longer
offers it — and `dut/lwip_dut/sweep-cases.sh` again emits only what the fixture can pass.

**Resolution.** The capability, and the audit note above that priced it at a fourth
resolution axis was wrong.

- **There is no fourth axis, because the backend never had to KNOW the fact.** The note
  reasoned over who can OBSERVE a capability — the backend class, or the DUT through 0x16 —
  and correctly found that neither can observe a second address. What it missed is that a
  backend-static word is ASSEMBLED AT CONSTRUCTION, so the third axis already accepts facts
  the backend is TOLD. `OpcodeUtControl` takes a `topology_caps` word and ORs it into
  `staticCapabilities()`; the factory decides it. The axis count is unchanged at three, and
  what grew is the set of INPUTS to one of them. `dut_capabilities.h` says so at the bit.
- **The premise became configured, which the note did name as an honest shape.**
  `Topology::dut_has_secondary_address()` (default `false`; `single_pc` returns `true`, and
  the comment there records that it is a fact about the netns TRANSPORT, since the pair
  provisions the alias whichever DUT is spawned into it) makes `dispatch.rs` emit
  `--expect dut.secondary_ip`, which lands in `DutIdentity::secondary_ip`.
- ⚠ **`cfg.ipv4.dut_alias_ip` was rejected as the discriminator, and this is the trap to
  keep.** It holds the same address and was already in the config, so it reads like the
  obvious source — but its own header says it is an EXPECTATION, the value a `--negative`
  row is allowed to FLIP. Deriving a capability from it would let a negative row silently
  revoke a capability, which is a hole, not a shortcut. Identity and expectation are
  separate fields for this reason, and the new field is an identity.

Measured 2026-09-25, both directions, because a capability that skips everywhere is
indistinguishable from one that works:

- **lwip-tap** — `SKIP UDP_USER_INTERFACE_07 — skip:requires_capability_0x2000_unavailable_on_opcode-ut`.
  The standing non-conclusion is now a skip that names the bit it lacks.
- **single-pc** (exit 0) — `PASS UDP_USER_INTERFACE_07`, and `PASS UDP_FIELDS_12`,
  `UDP_USER_INTERFACE_02`, `UDP_USER_INTERFACE_08` beside it. The three neighbours share
  `UdpDutOriginatedBase`, so they prove the declaration EXTENDED that base's value for one
  case rather than widening the base — a widened base would have skipped all four here.
- `capability_gate_audit.py --check`: 14 bits defined, 14 advertised, 14 with a demand
  vocabulary, 0 undeclared demands, 0 declarations with no demand. The last number is the
  one that proves the new demand is SEEN: the token is the alias constant `kDutAliasIp4Be`,
  and had the audit not matched it, the declaration would have reported as OVERDECLARED.
- The audit's `BACKEND_FILES` grew from one file to two, which is the shape of the change
  rather than an exemption for it: a capability word is no longer assembled in one place.

**The second done-when clause was answered by correcting the CONTRACT, not the list.** The
sweep still offers the case; the gate declines it at run time. Dropping it into
`inventory_overrides.json` instead would have put the same premise in two places, and the
two would drift — a list drop is frozen bookkeeping that a fixture GAINING the capability
would not undo, while the gate re-asks every run and starts exercising the case the day the
premise holds. So `sweep-cases.sh` now says it emits every case the fixture is ASKED, names
both dispositions, and records that the split between them is historical: several
`expected:false` reasons in that ledger are themselves missing UT opcodes, which is exactly
what the 0x16 axis reports, and they simply predate the gate.

⚠ **Residue, stated rather than hidden:** the alias VALUE is still compiled twice — the C++
constant and the SCXML `0x050010ACU` literal — while its PRESENCE is now a topology fact.
A topology declaring a DIFFERENT second address satisfies the capability and then fails the
guard. Registered as TD-48.

---

## TD-26 — the lwip-tap teardown reports "DUT ignored SIGTERM" for every DUT that obeyed it

**Status:** RESOLVED (2026-09-23). **Logged:** 2026-09-23, while closing TD-20 on lwip-tap.
The entry below is the debt as logged; **Resolution** at its end records what closed it.

**What it is.** `LwipTap::kill_dut` (`dut/env/orchestrator/src/topology/lwip_tap.rs`) sends
SIGTERM and then polls `pgrep -f <kill_name>` for 500 ms. It reaps the held `Child` only
after that loop. A DUT that exits promptly becomes an unreaped zombie, and `pgrep -f`
matches zombies. So the poll never sees the exit: the warning fires, and SIGKILL goes to a
process that has already exited.

Measured on 2026-09-23:

- A 12-case lwip-tap run printed the warning after all 12 cases.
- `/tmp/tc8-lwipfix-last-dut.log` holds 13 `SIGTERM — UT slots aborted, exiting` lines for
  13 DUT spawns, so every DUT ran its orderly teardown and exited.
- A standalone probe showed a child in state `Z` matched by `pgrep -f`, and no longer
  matched once it was reaped.

The earlier sweep's 349 warnings across 348 cases are the same artifact.

**Why it exists.** The name-based poll was written for the case where the DUT is not our
own child (the reap-selector matrix in the `topology` module docs). Here the fixture holds
the `Child`, so the process table cannot show a death the fixture has not reaped yet.

**Risk if left.** The warning is the only signal that a DUT's teardown really hung, which
would leave UT slots un-RST and tester halves in FIN-WAIT-2 on reused quads. Firing on every
case makes it noise, so a real hang would read like every other case. It also costs 500 ms
per case: about three minutes over a full lwIP sweep.

**Textbook fix.** Decide liveness from the handle the fixture already holds: poll
`Child::try_wait` on the held child, and fall back to the name-based poll only when nothing
is held. That also makes the SIGKILL fallback reachable only by a DUT that is really alive.

**Done when:** a lwip-tap run of any cases prints no "DUT ignored SIGTERM" warning while the
DUT log still shows one orderly `exiting` line per spawn, and a DUT made to ignore SIGTERM
still produces the warning and the SIGKILL.

**Resolution.** The fix went one level below `kill_dut`, because the defect came from a rule
nobody had written down: which oracle decides that a process has died.

- **The held child decides for itself.** `kill_dut` still signals by `kill_name`, but polls
  `dut_running`. That function asks the held `Child` through `try_wait`, which also reaps it,
  and asks the process table only about what no handle covers. On the SIGKILL fallback the
  held child is also killed by its own pid, so a `kill_name` that does not name it still
  reaches it.
- **A process-table poll never counts a zombie.** `proc::running_match` lists `pgrep -f`
  matches and drops any whose `/proc/<pid>/stat` state is `Z` or `X`. A zombie's cmdline is
  empty, so `-f` falls back to its comm. A NAME selector matches that comm; a symlink PATH
  selector never does. That is why `kill_by_marker` on single-pc never showed this defect:
  its path marker hid it rather than being correct. `kill_by_marker` now uses the same
  helper, and the reap-selector matrix in the `topology` module docs states the rule.
  ssh-remote already applied it with its own remote `ps` predicate.

Measured on 2026-09-23 with the built orchestrator and lwIP DUT:

- **Conforming DUT** (ICMPv4_TYPE_08, UDP_INTRODUCTION_03, TCP_BASICS_01, TCP_CALL_ABORT_02
  on lwip-tap): 4 PASS, **0** warnings. Before the fix, the same fixture printed one warning
  per kill. Each case's `.dut.log` (TD-27) holds exactly one
  `SIGTERM — UT slots aborted, exiting` line, and the run log holds 5: four cases and the
  spare.
- **DUT that ignores SIGTERM**: a scratch `[lwip] app` wrapper started the real DUT, set
  SIGTERM to ignored, waited for the DUT's orderly exit, then `exec`ed into `sleep`. That
  left the held pid alive and no longer matching `kill_name`. On 2 cases the run printed
  3 warnings for 3 kills (2 cases plus the spare) and then went on normally. There was no
  bounded-wait warning and no `sleep` survived, so the pid-scoped SIGKILL took. The name
  poll could not have seen this process, so only the handle could have raised these warnings.
- **single-pc** (ICMPv4_TYPE_08, SOMEIPSRV_FORMAT_01, through the changed
  `kill_by_marker`): 2 PASS, no "survived SIGKILL+confirm" warning.
- Unit tests: `proc::tests::a_zombie_matching_by_name_is_not_running` first asserts that a
  plain `pgrep -f` still matches the zombie, so the filter is really being tested.
  `lwip_tap::tests::a_held_dut_that_exits_is_not_running` covers the handle.

---

## TD-27 — a lwip-tap case's DUT log holds only the fixture banner, never the DUT's own output

**Status:** RESOLVED (2026-09-23). **Logged:** 2026-09-23, while working on TD-26.
The entry below is the debt as logged; **Resolution** at its end records what closed it.

**What it is.** On every other topology the per-case `<case>.dut.log` (in `--log-dir`, or in
the scratch work root) is the DUT's own stdout and stderr for that case. On lwip-tap,
`LwipTap::start_dut` (`dut/env/orchestrator/src/topology/lwip_tap.rs`) writes one provenance
line to it and nothing else. The DUT that served the case was spawned earlier, at bring-up or
in the previous case's `stop_dut`, with its output appended to the run-wide
`<FIX_DIR>/dut.log`. Teardown renames that file to `/tmp/tc8-lwipfix-last-dut.log`, and the
next run overwrites it.

**Why it exists.** The DUT is respawned between cases, so it starts before the path of the case
it will serve is known. The fixture never connected the spawn to that path afterwards.

**Risk if left.** The DUT's side of a case cannot be read next to that case's harness log and
pcap. A run's DUT output lives in one host-global file with every case mixed together, and the
next run loses it. TD-26's own Done-when ("one orderly `exiting` line per spawn") can only be
checked by counting lines in that shared file, not per case.

**Textbook fix.** Record where each spawn's output starts in the run log. When `start_dut` is
given the case's DUT log path, keep it with that spawn. Once `stop_dut` has killed and reaped
the spawn, its output is complete, so append that range to the case's DUT log. The run log
stays as the postmortem of the whole run.

**Done when:** a lwip-tap run with `--log-dir` leaves each case's `.dut.log` holding the
banner, then the lwIP DUT's own lines for that case, ending in its SIGTERM `exiting` line.

**Resolution.** Each spawn is now a `DutSpawn` that carries the run-log offset where its
output starts. `start_dut` records the case log path on the spawn that is up. `retire_dut`
kills and reaps the spawn, then appends its range of the run log to that case log. The copy
runs only after the reap, so the DUT cannot write anything more to it. The spare DUT spawned
after the last case serves no case and is left only in the run log.

Measured on 2026-09-23 with `--log-dir` on ICMPv4_TYPE_08, UDP_INTRODUCTION_03 and
TCP_BASICS_01 (all PASS). Each `.dut.log` holds the banner, `stack up`, that spawn's own
`rx_frames` count (37, 13 and 19, so no two spawns were mixed), and
`SIGTERM — UT slots aborted, exiting`. One correction to the Done-when: the `exiting` line is
not the last line. The DUT prints its lwIP stats dump after it, and that dump belongs to the
same spawn. The run log holds four `exiting` lines: three cases plus the spare.

---

## TD-28 — the Linux reference DUT's reassembly timer ignores arriving TTL, so IPv4_REASSEMBLY_11 fails there

**Status:** OPEN (accepted). **Logged:** 2026-09-24, from a run of the Linux known-fail set.

**What it is.** RFC 791 §3.2 sets a reassembly bucket's timer to `MAX(TLB, TTL)` on every
arriving fragment, so a fragment with a large TTL extends the bucket's life.
`IPv4_REASSEMBLY_11` sends the two halves of an Echo Request with TTL 255, three seconds
apart, against `ipfrag_time=2` (per-case conditioning in
`dut/env/orchestrator/src/conditioning.rs`). The Linux kernel arms the bucket timer from
`net.ipv4.ipfrag_time` alone (`net/ipv4/ip_fragment.c`, `ip_frag_queue`), so the bucket
expires at two seconds and the kernel reports it. Measured on 2026-09-24 on kernel
7.0.0-31-generic, single-pc: frag 0 at 00:12:12.808, an ICMP Time Exceeded code 1 from the
DUT at 00:12:14.810 quoting frag 0 (id 61462), and no Echo Reply. The case lands
`fail:reassembly_timer_not_extended_by_large_ttl`, an observed violation.

The lwIP fixture has the same deviation (a static `IP_REASS_MAXAGE`) and reached the same
verdict in the same session. Its evidence is in `dut/lwip_dut/README.md`, where that ledger
entry points.

**Why it exists.** The mark in `docs/spec/inventory_overrides.json` keeps a case the
reference DUT cannot pass out of the regression lane. A DUT that implements the extension
passes on the same wire shape. No sysctl couples the Linux timer to TTL, so conditioning
cannot move the reference DUT into a conforming mode, as `arp_accept` and
`tcp_syn_linear_timeouts` do for other cases.

**Risk if left.** Contained. The case still runs wherever it is not marked. On Linux it
concludes on the DUT's own report rather than on an absence, so if the kernel's behaviour
changes the case passes, and the ledger then has to explain that pass.

**Textbook fix.** None inside this repository. The kernel would have to couple the bucket
timer to arriving TTL.

**Done when:** the Linux kernel implements the RFC 791 §3.2 timer extension, so the
reference DUT passes `IPv4_REASSEMBLY_11` and the mark is removed.

---

## TD-29 — the Linux reference DUT points a Parameter Problem at the option's first octet, so ICMPv4_ERROR_02 fails there

**Status:** OPEN (accepted). **Logged:** 2026-09-24, from a run of the Linux known-fail set.

**What it is.** `ICMPv4_ERROR_02` sends an Echo Request carrying a malformed Timestamp option
(declared length 10, 8 octets on the wire) and grades the Parameter Problem's Pointer. TC8
names the value literally: the 20-octet base header plus the option's third octet, its
pointer field, which is 22. The Linux kernel reports the option's first octet instead
(`net/ipv4/ip_options.c`, `ip_options_compile`, which sets the error offset to the option's
start). Measured on 2026-09-24 on kernel 7.0.0-31-generic, single-pc: the DUT answered
within 150 µs with `ICMP parameter problem - octet 20`, and the case landed
`fail:parameter_problem_pointer_not_22`.

RFC 792 says only that the pointer "identifies the octet where an error was detected", so
both readings fit the RFC. TC8 fixes one of them, and the case grades the TC8 value. An
earlier version accepted either 20 or 22, which would also have passed a DUT that follows
Linux where TC8 asks for 22.

**Why it exists.** No sysctl selects the pointer convention, so conditioning cannot bring the
reference DUT onto the TC8 value. The mark in `docs/spec/inventory_overrides.json` keeps the
case out of the Linux regression lane. It still runs, and passes, on a DUT that reports 22.

**Risk if left.** Contained. The case concludes on an observed value, so a kernel that
changes its convention would show up as a pass.

**Textbook fix.** None inside this repository. Widening the pass condition back to {20, 22}
is not a fix; it is the defect the strict comparison was written to remove.

**Done when:** the Linux kernel reports the offending pointer octet (22 here), so the
reference DUT passes `ICMPv4_ERROR_02` and the mark is removed.

---

## TD-30 — the Linux reference DUT acknowledges an out-of-window RST in FIN-WAIT-2, so TCP_FLAGS_INVALID_15 fails there

**Status:** OPEN (accepted). **Logged:** 2026-09-24, from a run of the Linux known-fail set.

**What it is.** `TCP_FLAGS_INVALID_15` drives the DUT through eight connection states and, in
each one, sends a RST whose sequence number is 16 MiB past the window. RFC 793 §3.9 says an
unacceptable RST is dropped, so the case grades an absence: no RST and no pure ACK from the
DUT. The full-socket states pass. Once the DUT's application has closed and its FIN has been
acknowledged, Linux moves the connection to a timewait socket (FIN-WAIT-2 orphan, later
TIME-WAIT). There `tcp_timewait_state_process` (`net/ipv4/tcp_minisocks.c`) answers ANY
out-of-window segment, RST included, with a rate-limited duplicate ACK. Measured on 2026-09-24
on kernel 7.0.0-31-generic, single-pc: phase 4's RST at 00:12:39.576653 drew a DUT ACK 111 µs
later, and the case landed `fail:dut_emitted_response_to_otw_rst_in_fw2`. Phase 8 (TIME-WAIT)
takes the same kernel branch but is not reached once phase 4 has failed.

This fits the broader RFC 5961 reading ("challenge anything out of window") and conflicts with
RFC 793 §3.9, which is what TC8 grades.

**Why it exists.** No sysctl disables the timewait duplicate ACK
(`tcp_invalid_ratelimit` only spaces them), so conditioning cannot bring the reference DUT
onto RFC 793 here. An earlier version of the case graded only "no DUT RST" in these two
phases so that Linux would pass. That hid the deviation from every DUT, so it was reverted.

**Risk if left.** Contained. The case concludes on an observed segment, and phases 1-3 still
grade the full-socket path on Linux in any run that includes the case.

**Textbook fix.** None inside this repository. Narrowing the guard again would pass the
deviation on every DUT.

**Done when:** the Linux kernel drops an out-of-window RST on a timewait socket without
answering it, so the reference DUT passes `TCP_FLAGS_INVALID_15` and the mark is removed.

---

## TD-31 — the Linux reference DUT resets new data on an orphaned FIN-WAIT-2, so TCP_UNACCEPTABLE_10 fails there

**Status:** OPEN (accepted). **Logged:** 2026-09-24, from a run of the Linux known-fail set.

**What it is.** `TCP_UNACCEPTABLE_10` closes the DUT's side, lets the tester acknowledge the
FIN so the DUT reaches FIN-WAIT-2, and then sends two segments. The first has an
out-of-window SEQ. The second has an in-window SEQ, four bytes of data and an unacceptable
ACK. RFC 793 §3.9 answers both with an empty ACK, and TC8 grades that. Linux has already
replaced the closed connection with a timewait socket in its FIN-WAIT-2 substate, and
`tcp_timewait_state_process` (`net/ipv4/tcp_minisocks.c`) resets any segment that brings new
data after a half-duplex close. It checks for new data before it looks at the ACK, so the
second segment gets a RST. Measured on 2026-09-24 on kernel 7.0.0-31-generic, single-pc: the
first segment drew an ACK 80 µs later, the second drew `Flags [R]` 74 µs later, and the case
landed `fail:dut_rst_to_unacc_ack_finwait2`.

RFC 1122 §4.2.2.13 says a TCP SHOULD send a RST when data arrives after the application has
closed, so the kernel is following one RFC's rule where TC8 grades another's. The conflict
comes from the stimulus: the spec's segment carries data.

**Why it exists.** No sysctl changes this branch, so conditioning cannot bring the reference
DUT onto the TC8 expectation. Sending the segment with no payload would avoid the branch, but
it would no longer be the stimulus the spec describes.

**Risk if left.** Contained. The case concludes on an observed segment.

**Textbook fix.** None inside this repository.

**Done when:** the Linux kernel answers an unacceptable ACK on an orphaned FIN-WAIT-2 with an
empty ACK before it applies the new-data reset, so the reference DUT passes
`TCP_UNACCEPTABLE_10` and the mark is removed.

---

## TD-32 — lwIP creates no ARP entry from a gratuitous Response, so ARP_05, ARP_06 and ARP_33 fail on the lwIP fixture

**Status:** OPEN (accepted). **Logged:** 2026-09-24, from a lwip-tap run of the lwIP known-fail
ARP set.

**What it is.** All three cases inject gratuitous ARP Responses for the tester's address into a
cold DUT cache, then have the DUT send to that address, and grade that it does so without
asking. lwIP's `etharp_input` (`src/core/ipv4/etharp.c`) updates an existing entry from any ARP
frame but creates one only when the DUT is the target (`for_us`), which is the literal RFC 826
reception algorithm. A gratuitous Response targets its own sender, so the cache stays cold.
`ARP_33` sends two such Responses and fails the same way. Measured on 2026-09-24, lwip-tap:
in `ARP_05` the Response at 00:14:18.714 was followed at 00:14:20.215 by the DUT's own
broadcast `who-has 172.16.0.1`. In `ARP_33` the second Response at 00:14:29.871 was followed
at 00:14:31.372 by the same Request. The verdicts were
`fail:dut_arp_request_after_gratuitous_learning` (ARP_05, ARP_06) and
`fail:dut_arp_request_after_double_injection` (ARP_33). `dut/lwip_dut/README.md` ("Verified
lwIP deviations") has the source reading, and why `ARP_34` passes on this fixture.

Learning from a gratuitous Response goes beyond RFC 826. The Linux reference DUT meets it only
through per-case `arp_accept=1` conditioning.

**Why it exists.** lwIP has no option that creates entries from unsolicited ARP, and this
repository never patches the vendored lwIP core, so the fixture cannot be conditioned the way
the Linux reference is. The marks in `dut/lwip_dut/inventory_overrides.json` keep the three
cases out of the lwIP sweep.

**Risk if left.** Contained. The cases conclude on an observed ARP Request.

**Textbook fix.** None inside this repository.

**Done when:** lwIP gains a configuration that creates a cache entry from a gratuitous ARP
Response, the fixture enables it, and `ARP_05`, `ARP_06` and `ARP_33` pass on lwip-tap with
their marks removed.

---

## TD-33 — the Linux reference DUT silently discards an overlapping reassembly queue, so IPv4_REASSEMBLY_13 cannot conclude there

**Status:** OPEN (accepted). **Logged:** 2026-09-24, from a run of the Linux known-fail set.

**What it is.** `IPv4_REASSEMBLY_13` sends four fragments of one Echo Request: offset 0, a
24-octet fragment at offset 2 with wrong data, an 8-octet fragment at offset 2 with the right
data, and the last fragment at offset 3. RFC 791 §3.2's example procedure resolves the
overlap in favour of the most recent data and reassembles, so the grade is an Echo Reply
carrying the right 27 octets. Since the CVE-2018-5391 hardening (kernel 4.18) Linux instead
discards the whole queue, fragment 0 included, as soon as the third fragment overlaps
(`net/ipv4/ip_fragment.c`, `ip_frag_queue` → `inet_frag_kill`). The last fragment starts a
new queue that never holds fragment 0, so when it expires the kernel sends no Time Exceeded
either. The DUT says nothing at all.

Measured on 2026-09-24 on kernel 7.0.0-31-generic, single-pc: the four fragments at +0.000,
+0.200, +0.401 and +0.601 s, then no frame from the DUT for the rest of the 5 s window.
The case lands `inconclusive:no_echo_reply_after_overlap_reassembly`.

**Why it exists.** The case grades a DUT's own report where one exists. lwIP lets the
overlapped bucket expire and reports it, and reaches
`fail:overlapping_datagram_discarded_by_reassembly_timeout`. Linux leaves only an absence,
and an absence is not a fail. So the Linux mark in `docs/spec/inventory_overrides.json`
holds back a NON-CONCLUSION, not a fail: the category TD-23 names. It is kept because
the reason for the non-conclusion is a verified property of the DUT, not a gap in the
harness. No sysctl makes the kernel keep an overlapped queue, and the only wire-visible
alternative would be a different stimulus than the one the spec describes.

**Risk if left.** Contained, with one caveat. If the kernel changed its overlap policy, the
case would start passing unseen while the mark is in place. That is the staleness TD-23
exists to catch.

**Textbook fix.** None inside this repository.

**Done when:** the Linux kernel reassembles an overlapped IPv4 datagram (or reports
discarding it), so the reference DUT concludes on `IPv4_REASSEMBLY_13` and the mark is
removed or re-argued on the verdict it then reaches.

---

## TD-34 — case comments cite rationale notes that live outside the repository

**Status:** RESOLVED (2026-09-24). **Logged:** 2026-09-24, while moving the known-fail
justifications in-tree (TD-28 to TD-33). The entry below is the debt as logged; **Resolution** at
its end records what closed it.

**What it is.** Comments in the case sources point a reader at notes this repository does not
hold: `reference_<topic>.md` files, or "`<topic>` memory", from a private note store. On
2026-09-24 a search over `src/`, `tests/`, `dut/`, `include/`, `tools/` and `unit_tests/`
found 42 such sites in 41 files, citing 13 distinct notes. The most-cited are
`reference_icmp_packet_host_gate.md` (12 sites), `reference_sce_captured_arg.md` (11) and
`reference_active_open_port_quad_collision.md` (8). The search was
`git grep -nE 'reference_[a-z0-9_]+(\.md| memory)|[a-z_]+ memory for|memory/[a-z_]+\.md'`. The
`memory/…` strings in `tools/debt_census.py` and `unit_tests/spec_inventory_test.cpp` are
test fixtures, not pointers, and are not counted.

A related, smaller defect sits beside some of them: `tcp_unacceptable_04.h`,
`tests/tcp_unacceptable_04/tcp_unacceptable_04.scxml` and
`tests/tcp_unacceptable_08/tcp_unacceptable_08.scxml` still say the case "is excluded from CI
green via grep filter in .github/workflows/smoke-test.yml". Neither case carries a mark any
longer, and no such filter exists.

**Why it exists.** The notes were written during investigations and cited from the code they
explained. `platform_known_fail_ref` gained a resolution check (`tools/debt_census.py`
`ref_resolves`), but a comment has no such check, so nothing ever asked whether the pointer
could be followed.

**Risk if left.** A reader of this repository, or anyone it is published to, meets a
justification they cannot read. The claims next to the pointers go stale unseen, as the
three grep-filter sentences already have.

**Textbook fix.** Bring each note's substance in-tree, next to the design it explains (a
`docs/` page or the owning header), and repoint every site. Then make the class checkable:
a pre-commit audit that rejects a comment citing a `reference_*.md` or "memory" note the tree
does not hold, the comment-side equivalent of `ref_resolves`.

**Done when:** the search above returns no site outside the two test fixtures, the three
grep-filter sentences are gone, and a pre-commit check rejects a new out-of-tree note
pointer.

**Resolution.** Each note's substance now sits where the code it explains lives, and every site
points there. The notes cited from many places got an owner: the SCE guard-rewrite rules in
`docs/scxml_guard_expressions.md` (checked against generated `.inl`), the Linux PACKET_HOST gate
at `Ipv4FrameSpec::dst_mac`, the TCP port-quad history in `tcp_active_open_offsets.def`, the ETS
extension seams in `docs/ets_dut_extension_seams.md`, and the DUT control seam in
`docs/dut_control_seam.md`. A single-site note became a sentence at its site. Bringing the facts
in exposed stale claims, which were corrected against a run, not transcribed:
`TCP_UNACCEPTABLE_04` passes on kernel 7.0 (ESTABLISHED now acknowledges the unacceptable ACK), the
harness no longer drops an empty UDP datagram, and `kBasicsActiveLocalPort` was not fixed per case.
The grep-filter sentences were four, not three (`tcp_unacceptable_08.h` held the fourth).

The search above measured one shape. The class was wider: 103 findings at `ae908462` once measured
with `tools/intree_pointer_audit.py`, including `project_`/`feedback_` notes, 14
`timing_serial_ref` values in `docs/spec/inventory_overrides.json`, ignored `claudedocs/` design
notes cited from 16 sites, TD-17's own justification, and published site text. All resolve now.
That audit is the check: it runs in pre-commit and in `build-test.yml`, scans every tracked file
whole, fails closed, and allows exemptions only as (file, token) pairs with a reason.

---

## TD-35 — the positive reassembly cases throw away the DUT's own report that it discarded the datagram

**Status:** RESOLVED (2026-09-24). **Logged:** 2026-09-24, while making `IPv4_REASSEMBLY_11`
and `_13` conclude. The entry below is the debt as logged; **Resolution** at its end records what
closed it.

**What it is.** The IPv4 fragment cases share `Ipv4FragmentEchoBase`, whose dispatch forwards
only Echo Replies to the SCXML. A DUT that fails to reassemble and lets the bucket expire
sends an ICMP Time Exceeded code 1 quoting fragment 0 (RFC 792). That report is the DUT
saying it discarded the datagram, which is an observation. The base drops it, so the case sees
only a missing Echo Reply and times out to inconclusive. `IPv4_REASSEMBLY_11` and `_13` now
forward the report (`dispatchEchoReplyOrReassemblyExpiry`,
`src/sce_integration/include/sce_integration/ipv4_fragments_common.h`) and grade it as a
fail. Four cases that grade successful reassembly do not: `IPv4_FRAGMENTS_01`,
`IPv4_REASSEMBLY_04`, `IPv4_REASSEMBLY_10` (phase A) and `IPv4_REASSEMBLY_12`. `_12` is
the sharpest. It exists to catch a DUT that SHRINKS the timer on a low-TTL fragment, and
that DUT would report the early expiry on the wire and still be graded inconclusive.

**Why it exists.** Forwarding the report from the base is unsafe. The absence cases built on
`tests/_templates/icmpv4_negative_absence.sce-template.xml` (`IPv4_REASSEMBLY_06/07/09`
among them) send ANY DUT-origin ICMP to `fail_dut_replied`. For them a Time Exceeded can be
the conforming outcome. So each case has to opt in with a guard that gives the report its
meaning, and only two have been done.

**Risk if left.** Each of the four reports a discard as a non-conclusion, which renders as
JUnit `<skipped>` and is green. Neither reference DUT hits this today, because both pass the
four, so the loss is on the DUTs the suite exists to grade.

**Textbook fix.** Give each of the four the REASSEMBLY_11 shape: override `dispatch` with
`dispatchEchoReplyOrReassemblyExpiry`, and add a fail transition for Time Exceeded code 1
from the DUT that quotes the case's own IP Identification (`Icmpv4Captured::quotes_ip_id`).
`_10` needs it on phase A only, since phase B expects the bucket to expire.

**Done when:** the four cases grade a DUT-origin Time Exceeded code 1 that quotes their own
fragment as a fail, and each still passes on single-pc and lwip-tap.

**Resolution.** Closed at what produced the four gaps rather than case by case. The report was
dropped by default because the base had no way to know what it meant, and a default either way is
wrong for some case. Every case on `Ipv4FragmentEchoBase` must now DECLARE
`kReassemblyExpiry` (`ReassemblyExpiryRole`, `ipv4_fragments_common.h`). There is no default, and a
missing declaration fails to compile with a message naming what to declare. The base's `dispatch`
forwards the report only to a `kGraded` case, and the per-case `dispatch` overrides of `_11` and
`_13` are gone. So the next fragment case cannot be written without deciding. The twelve cases
declare:

- `kGraded`: the four above (each with a new fail final keyed on its own IP Identification;
  `_10` on phase A only) plus `_11` and `_13`.
- `kNotGraded`: `IPv4_REASSEMBLY_06/07/09`, where the report may be the conforming outcome, and
  the compound `IPv4_FRAGMENTS_02/03/04`, where it only says a precondition bucket died.

`Ipv4ReassemblyFaultNegBase` declares `kGraded` for the eight `_11`/`_13` mutants.

**Runs (2026-09-24).**

- **single-pc:** the twelve positives give 10 pass. `_11` fails and `_13` is inconclusive, both
  unchanged (TD-28, TD-33). The seven fragment negative rows all land.
- **lwip-tap:** the twelve positives and the eight mutants give 17 pass. The three failures,
  `IPv4_FRAGMENTS_04`, `_11` and `_13`, are the fixture's `platform_known_fail` entries.

A timing question the entry did not ask was settled by `IPv4_REASSEMBLY_10`'s trace. A report sent
during a BLOCKING stimulus is still dispatched once the listen window opens: its phase-B expiry
report reached the SCXML, was dropped for want of a transition, and the case passed. So `_10`
phase A and `_12` see their reports without being rescheduled, and `_11`'s comment claiming
otherwise was corrected. The four new fail finals are reached by no run yet, because both reference
DUTs reassemble correctly; that is TD-41.

---

## TD-36 — seven DHCP files are bound to a TC8 §4.4.5 that does not exist

**Status:** RESOLVED (2026-09-24). **Logged:** 2026-09-24, when rewrapping a comment in
`tests/_templates/dhcpv4_renewing_retx_field.sce-template.xml` left its §4.4.5 binding
unbacked. The entry below is the debt as logged; **Resolution** at its end records what closed it.

**What it is.** TC8's §4.4 (IPv4) has four subsections, 4.4.1 to 4.4.4, per the TC8 v3.0
table of contents (the spec is members-only; this repository holds none of its text). The only
"4.4.5" in the spec text is a row of the RFC 2131 cross-reference table. The atomic store
(`docs/.atomic/workspace.atomic.json`) nevertheless holds a section `4.4.5`, "auto-seeded
TC8-internal sub-section", with 7 `implements` bindings. Every one of the 7 files cites
RFC 2131 §4.4.5 (RENEWING / REBINDING, T1 and T2), not TC8. The citation is either wrapped
across a line (`(RFC` / `2131 §4.4.5)`) or bare after an earlier RFC section
(`§4.3.2 (...) / §4.4.5`), so `validate-code-refs` does not see the `RFC` prefix and reads it
as a TC8 section. The 7 files: `dut/dut_service/dhcpv4_client.cpp`,
`dut/dut_service/dhcpv4_client.h`, `src/sce_integration/include/sce_integration/dhcpv4_captured.h`,
`tests/_templates/dhcpv4_post_bound_discover.sce-template.xml`,
`tests/_templates/dhcpv4_rebinding_retx_field.sce-template.xml`, and the
`dhcpv4_client_reacquisition_03` / `_04` SCXMLs. An eighth, the renewing retx template, lost
its binding on 2026-09-24 (commit `6724bceb`) once its citation was rewrapped onto one line.

**Why it exists.** Same origin as the 7 unbound phantom sections `mnemosyne.toml` records next
to `severity_coverage`: RFC citations split across lines were seeded as TC8 sections at
adoption. That record covers only the phantoms left UNBOUND. A phantom that keeps its
misread bindings raises no warning at all, so it was never counted.

**Risk if left.** The store claims seven files implement a TC8 section that has no text,
and the coverage view counts §4.4.5 as implemented. Any other section kept alive this way is
equally invisible. Only §4.4.5 was measured; the TOC is three levels deep in most chapters,
so it cannot by itself say which deeper store sections are phantoms.

**Textbook fix.** Rewrite each of the 7 citations so `RFC 2131` stands on the same line as
the section number, then `remove-section-binding` each pair. §4.4.5 then joins the unbound
phantoms, and `mnemosyne.toml`'s count of them must be raised to 8. The section itself
cannot be deleted here: `mnemosyne-cli` has no remove-section verb.

**Done when:** no binding to §4.4.5 remains, `validate-code-refs` reports no
binding-class violation, and `mnemosyne.toml` names §4.4.5 among the phantom sections.

**Resolution.** All seven files meant RFC 2131 §4.4.5, so none could be repointed to a TC8
section; each binding was removed with `remove-section-binding` and its reason. Removing them let
the gate name the exact misread line in each file, one per file. Five had "RFC" and "2131 §4.4.5"
split across a line break, two named a bare "§4.4.5" after an earlier RFC citation. Each now reads
"RFC 2131 §4.4.5" on one line, and one of them lost a doubled "RFC 2131 RFC 2131". Lines that
already carried the prefix on the same line were never misread and are unchanged. §4.4.5 now has
no binding and joins the unbound warn surface. `mnemosyne.toml`'s record of that surface was
itself wrong: of its "7 phantom sections", three (§4.2.2, §4.2.3, §4.4.1) are real TC8 prose
sections that no code implements. It now lists 5 phantoms and 3 unimplemented prose sections,
each checked against the TC8 table of contents.

---

## TD-37 — `--vs-spec` counts a case as covering the TC8 spec whatever suite registered it

**Status:** RESOLVED (2026-09-24, with TD-38). **Logged:** 2026-09-24. Found 2026-09-18 while
judging a consumer's cross-suite case-alias request, recorded then only outside this repository,
and re-verified in-tree at `b324d50f`. The entry below is the debt as logged; **Resolution** at its
end records what closed it.

**What it is.** Case identity is `(suite, id)` in `CaseRegistry`, but the coverage report drops the
suite. `--list-cases --vs-spec` builds its registered set in
`src/cli/commands/test_command.cpp` from `listSorted(/*include_deprecated=*/true)` as
`canonicalise(e->id)`, with no suite, and the `test` subcommand has no `--suite` flag to scope it.
So an injected suite's `ARP_03` marks the TC8 spec's ARP_03 as registered from a catalog that is not
TC8's, and a consumer's own ids land among registered-but-not-in-spec unless `--inventory-extra`
supplies a matching inventory.

**Why it exists.** Only one suite has ever been registered in a shipped build, so an id was an
identity. The registry learned the suite; the report did not.

**Risk if left.** Latent while one suite is registered (today `543 / 543`, missing 0). With a second
suite, the CI spec-coverage gate (`--vs-spec --strict`) can pass on a case the TC8 catalog does not
register.

**Textbook fix.** One catalog per report: give `test` a suite scope, and have `--vs-spec` count only
the scoped suite's entries (default: the in-tree suite).

**Done when:** `--vs-spec` counts only the scoped suite, and a unit test with two registered suites
proves an injected suite's same-id case does not mark the TC8 spec case registered.

**Resolution.** Closed at the base TD-38 names rather than in the report: the report could not be
scoped while the inventory it measures against had no suite to scope by. `SpecInventory` now
attributes every case to a suite (an extra file's root `"suite"`, default the in-tree one) and
resolves by `(suite, id)` only. The report's computation moved out of `runVsSpecReport` into
`computeSpecCoverage` (`src/sce_integration/spec_coverage.cpp`), which takes the suite and counts
only that suite's registered cases against that suite's catalog. It refuses a suite the inventory
holds no catalog for, because an empty report would read as full coverage. `test` gained `--suite`.
`--vs-spec` defaults to the in-tree suite, so the CI gate still reads `543 / 543` and its output is
unchanged. `unit_tests/spec_coverage_test.cpp` registers two suites and shows that `demo:ARP_03`
leaves the TC8 spec's ARP_03 missing, and that the demo suite is measured against its own catalog.

---

## TD-38 — the inventory axes resolve by case id alone, so a same-id case in another suite inherits them

**Status:** RESOLVED (2026-09-24, with TD-37). **Logged:** 2026-09-24, found and re-verified as
TD-37. The entry below is the debt as logged; **Resolution** at its end records what closed it.

**What it is.** Every axis in `docs/spec/inventory_overrides.json` (expect overrides, negative rows,
`vsomeip_cfg`/`vsomeip_env`, `timing_serial`, `platform_known_fail`, `expected:false`) is looked up
through `specCaseFor` (`src/cli/commands/test_command.cpp`), which calls
`SpecInventory::find(canonicalise(id))` with the case id alone. A case in an injected suite whose id
matches an in-tree one inherits the TC8 entry: its stimulus changes, its DUT is provisioned for the
TC8 case, and a `platform_known_fail` excuses its failure. A case whose id does not match inherits
nothing. Measured on 2026-09-18 over what were then 144 override entries, 136 carried an axis that
changes execution or lane routing, and 15 of them provision the DUT.

**Why it exists.** Same as TD-37: the overrides file was written when the in-tree suite was the only
one. TD-17 is this defect's orchestrator-side sibling for the vsomeip flavor table.

**Risk if left.** Latent while one suite is registered. With a second, a consumer's row can be
silently excused, or run a different stimulus than its name says. Nothing in the verdict shows it.

**Textbook fix.** Key the lookup on `(suite, id)`: the in-tree overrides apply to the in-tree
suite, and an injected suite carries its own (`--inventory-extra`). The axes differ in effect, so
decide the resolution per axis, not per entry: one entry can carry several
(`SOMEIPSRV_OPTIONS_11` and `SOMEIPSRV_SD_MESSAGE_13` each hold a stimulus override and a
negative row).

**Done when:** a case in a non-default suite resolves no in-tree axis unless its own inventory
supplies it, and a unit test with two suites sharing an id proves it.

**Resolution.** The inventory itself had no suite. Extra files were merged into one id map and
had to be disjoint from the TC8 ids, so an injected suite could not even ship a catalog for a
reused id. Lookups by id alone were the only kind that could exist. Now a case's key in
`SpecInventory` is `(suite, canonical id)`, `find` takes both, and the id-only `find` is gone, so
no caller can resolve the old way. Within one suite, ids must still be disjoint. Across suites the
same id is legal. An overrides key is bare for the in-tree suite and `suite:ID` for any other (the
token `--case` already accepts), and it applies to that one suite's case. `runCase`,
`--list-cases` and both `--list-*` exposers resolve through the registered entry's own suite. The
exposers print a non-default suite's rows as `suite:ID`, as `--list-cases` does. The in-tree
output is unchanged. The per-axis decision is written down in `spec_inventory.h`: every axis is
either the case's own stimulus and verdict or how one DUT behaves under that stimulus, so none
crosses a suite boundary. The suite name's SSOT moved to `case_suite.h`, a dependency-free header,
so the inventory can share it without the registry's runner dependencies. The CMake derivation of
`TC8_DEFAULT_SUITE` now reads it there. `unit_tests/spec_inventory_test.cpp` gives two suites the
same id and one in-tree override that sets every axis. The demo case resolves none of the axes.
Without its own catalog it resolves to nothing. A qualified override reaches only its own suite.

---

## TD-39 — an injected case that reuses a flavored in-tree id cannot declare that it needs the base DUT

**Status:** RESOLVED (2026-09-24). **Logged:** 2026-09-24, while resolving TD-17. The entry below
is the debt as logged; **Resolution** at its end records what closed it.

**What it is.** TD-17's rule refuses a non-default token such as `demo:SOMEIPSRV_RPC_14` whose suite
declares no flavor of its own when the in-tree id carries one. The refusal message says how to
clear it: declare the case's own flavor under the key `demo:SOMEIPSRV_RPC_14`. That works for a
case that needs a flavor. A case that needs the plain base DUT (base vsomeip config, no
`TC8_DUT_*` env) cannot say so. `runListVsomeipVariants` (`src/cli/commands/test_command.cpp`)
skips every case whose `vsomeip_cfg` and `vsomeip_env` are both empty, and the loader reads an
absent field and an empty one alike (`findStringField` returns empty for both). So "this case
declares the base flavor" and "this case declares nothing" produce the same listing.

**Why it exists.** Before suites, "no row" could only mean the base config. With the refusal,
"no row" now also means "unknown", and the listing has no third state.

**Risk if left.** Latent: no shipped build registers a second suite. Once a consumer does, a
same-id case that needs the base DUT is refused on every run, with no remedy except renaming the
case. The failure is loud, not silent, so no verdict is wrong. The case simply cannot run.

**Textbook fix.** Make the axis's presence visible, not just its value. The loader records whether
an overrides entry names `vsomeip_cfg` or `vsomeip_env` at all. The exposer emits a row for every
case that names the axis, so `demo:ID||` becomes a declared base flavor, and the orchestrator's
own-row branch then resolves it to the base config. Both drivers already parse an empty cfg and
empty env as "keep the base".

**Done when:** an overrides entry that names the vsomeip axis with empty values produces a
`--list-vsomeip-variants` row, a harness unit test proves absent and empty differ, and an
orchestrator test proves `demo:ID` with such a row resolves to the base flavor instead of being
refused.

**Resolution.** The axis now records its presence as well as its values. `SpecCase::vsomeip_declared`
is set when an overrides entry names `vsomeip_cfg` or `vsomeip_env` at all, and
`--list-vsomeip-variants` prints a row per declaration, so `demo:ID||` is a declared base DUT.

An injected case that reuses a flavored in-tree id now has a way to declare every choice, under its
own `suite:ID` key:

- the in-tree case's values, to want that flavor;
- other values, for a flavor of its own;
- both empty, for the base DUT.

The orchestrator's own-row branch resolves all three, and its refusal message names them. Nothing
travels between catalogs by id, and pointing at another catalog's entry stays the consumer's alias
DRAFT (TD-17).

**Runs (2026-09-24).**

- `spec_inventory_test` (16) passes, including `EmptyVsomeipAxisIsADeclarationNotAnAbsence`.
- `cargo test` in `dut/env/orchestrator` passes 86, including
  `another_suite_declaring_the_base_dut_is_not_refused`.
- With a demo inventory and an overrides file declaring `demo:SOMEIPSRV_RPC_14` empty, the
  harness prints `demo:SOMEIPSRV_RPC_14||`, and no row for a demo case with no declaration.
- The in-tree `--list-vsomeip-variants` is byte-identical at 15 rows.

---

## TD-40 — an explicit `--inventory-overrides` path that does not exist is read as "no overrides"

**Status:** RESOLVED (2026-09-24). **Logged:** 2026-09-24, while adding the orchestrator's
passthrough for TD-17. The entry below is the debt as logged; **Resolution** at its end records what
closed it.

**What it is.** `SpecInventory::load` (`src/sce_integration/spec_inventory.cpp`) treats a missing
overrides file as none at all ("Missing file is OK"). `TestCommand` passes the default path
`docs/spec/inventory_overrides.json` when the flag is absent, and the flag's own value when it is
given, and all five of its load sites repeat that choice. Nothing tells the two apart. So
`tc8-harness test --inventory-overrides lwip_typo.json --list-cases --exclude-platform-known-fail`
lists every case as if no platform were known to fail anything. A per-case run likewise drops its
expect overrides and its negative row, and nothing on the console says why. The orchestrator's
new passthrough checks its own flag before calling the harness. A direct harness caller (CI's bash
drivers, a consumer's script) gets no such check.

**Why it exists.** The tolerance serves the unflagged case, which falls back for a stripped
environment in which `--list-cases` still works with `-` sections. It was never narrowed to that
case. The five copies of the default-path choice are why nobody could.

**Risk if left.** A typo in a platform overrides path silently drops every axis that file
carries: platform known-fails, cadence routing, stimulus overrides and negative rows. It turns
excluded failures into apparent new failures, or makes a negative run fail loudly for the wrong
reason.

**Textbook fix.** One place in `TestCommand` resolves the inventory paths and loads the inventory.
It is used by all five sites, and it refuses an EXPLICIT overrides path that does not name a file,
leaving the default path's tolerance where it is.

**Done when:** `test --inventory-overrides <missing>` exits non-zero with an error naming the path
on every mode that loads the inventory, the default-path fallback is unchanged, and the five load
sites share one loader.

**Resolution.** The two halves of the decision now live where each is known:

- `SpecInventory::load` is strict. A non-empty overrides path must open, and an empty one means "no
  overrides file".
- `TestCommand::loadInventory` is the one loader the five sites call, and the only code that knows
  a path was a default. It passes the default overrides file only if it exists. It reports
  "stripped" only when the default inventory itself is absent.

That stripped case is the only one where a best-effort mode degrades: `--list-cases` with no filter,
and a case run, which in a stripped tree has no per-case axes to lose. Anything else fails, including
a named file and a file that exists but does not parse. Before this, both modes ran on silently when
the overrides file did not parse, and a case run then dropped the stimulus overrides and negative row
it asked for.

**Runs (2026-09-24).** With `--inventory-overrides <missing>`, all six modes (`--list-cases`,
`--list-cases --exclude-platform-known-fail`, `--vs-spec`, `--list-neg-rows`,
`--list-vsomeip-variants`, `--case`) exit non-zero with an error naming the path. Six listings are
byte-identical to the TD-37/38 binary, the lwIP overrides file among them. In a tree with no
`docs/spec`, `--list-cases` still warns and lists 761 cases, while `--exclude-deferred` fails.
`spec_inventory_test` (15) passes, including `NamedOverridesThatCannotOpenIsError`.

---

## TD-41 — the four reassembly-discard fail finals are reached by no run

**Status:** RESOLVED (2026-09-24). **Logged:** 2026-09-24, while resolving TD-35. The entry below
is the debt as logged; **Resolution** at its end records what closed it.

**What it is.** TD-35 gave four positive cases a fail final for the DUT's own Time Exceeded code 1
quoting their fragment 0:

- `IPv4_FRAGMENTS_01` `fail_datagram_discarded`
- `IPv4_REASSEMBLY_04` `fail_datagram_discarded`
- `IPv4_REASSEMBLY_10` `fail_phase_a_datagram_discarded`
- `IPv4_REASSEMBLY_12` `fail_timer_shrunk`

Both reference DUTs reassemble these cases correctly, so no run reaches the finals. The four cases
are dispositioned by negative rows that flip `icmpv4.echo_id`, and those rows prove only the Echo
Reply guards. So nothing proves the discard guard fires: its IP Identification constant, its
`src_ip` conjunct and its forwarding by the `kGraded` declaration. `IPv4_REASSEMBLY_11`/`_13` had the
same gap until `_11_NEG`/`_13_NEG` reached theirs on lwIP.

**Why it exists.** The guard asserts DUT behaviour a conforming DUT never shows. Only a fault seam
can produce it, and TD-35's Done-when asked for grading, not reachability.

**Risk if left.** A wrong constant or a broken conjunct would leave a real discard graded as a
timeout again, silently: the TD-35 defect, back in a form no run can see. The dispatch half is
shown working (the `IPv4_REASSEMBLY_10` trace, TD-35); each guard is not.

**Textbook fix.** Add the `_11_NEG` shape per case: arm `kIpv4FaultDropLastFragment` on the lwIP
fixture so the bucket expires and lwIP reports it, and pass on that report. Adding a `_NEG` makes a
multi-final case FAULT_INJECTION. `negative_coverage_audit.py` then requires a
`tools/fault_injection_coverage.json` entry mapping EVERY fail final to a mutant, so the echo
id/seq/data finals need egress-fault mutants too, as `_11_NEG2`..`_NEG4` are.

**Done when:** each of the four finals is the verdict of a `_NEG` mutant that passes on lwip-tap,
and `negative_coverage_audit.py --check` accepts the four cases' coverage entries.

**Resolution.** Each case now has a lwIP `_NEG` in the register's FAULT_INJECTION shape:
`IPv4_FRAGMENTS_01_NEG` and `IPv4_REASSEMBLY_04_NEG`, `_10_NEG` and `_12_NEG`. Each arms
`kIpv4FaultDropLastFragment`, sends the positive's own fragments and passes on the report the
positive grades. `_10_NEG` sends phase A alone. The stimuli the positives sent inline moved into
shared emitters in `ipv4_reassembly_common.h`, so each positive and its `_NEG` send one set of
frames.

The textbook fix above was wrong on one point. A `_NEG` does not make these cases FAULT_INJECTION:
a case with a negative row stays SOUND_ROW, so the audit never asked for their coverage entries.
It also rejected any entry that did not cover every final, which these four could not do: their
Echo Reply finals other than the row's are unproven, and were before TD-35. So the audit now
accepts a PARTIAL entry for a SOUND_ROW case. Its keys must be real fail finals and its values
real `_neg` siblings, and completeness stays required for FAULT_INJECTION. The four entries record
exactly the link TD-41 is about. The finals no mechanism proves are TD-42.

**Runs (2026-09-24).**

- **lwip-tap:** the four `_NEG` pass, each on a type 11 code 1 frame from the DUT, per its trace.
  Of the twelve fragment positives, nine pass and three are the fixture's `platform_known_fail`
  (`IPv4_FRAGMENTS_04`, `_11`, `_13`), unchanged.
- **single-pc:** the four positives pass after the stimulus refactor. The four `_NEG` skip for want
  of `kCapIngressFault`, like every other lwIP-only mutant.
- `negative_coverage_audit.py --check` is OK. Fed an entry naming a final the case lacks, or a
  `_neg` of another case, it rejects both.

The four `_NEG` join the smoke workflow's lwip-tap list, so CI runs them.

---

## TD-42 — a negative row proves one fail final, and the audit counts its whole case as disposed

**Status:** RESOLVED (2026-09-24). **Logged:** 2026-09-24, while resolving TD-41. TD-41 was one
instance of it. The entry below is the register as logged; the resolution follows it.

**What it is.** `tools/negative_coverage_audit.py` gives each positive case ONE disposition, and a
case with a negative row is SOUND_ROW (rows take precedence). A row flips one expectation and lands
on one fail final. For a single-final case that proves the guard. For a multi-final case it proves
only the final the row lands on, and the audit still counts the case as disposed. The audit's own
rule that one mechanism proves one final (`validate_fault_coverage`, PARTIAL_FAULT_INJECTION)
binds FAULT_INJECTION cases only.

Measured 2026-09-24, after TD-41: 18 SOUND_ROW cases carry more than one fail final. 33 of their
finals are proven by neither a row nor a mapped `_neg`. The cases are `ARP_04`, `ARP_06`,
`ARP_32`, `ARP_33`, `ARP_34`, `ARP_35`, `ARP_39`, `ARP_40`, `ARP_45`, `ARP_49`, `ICMPv4_TYPE_12`,
`IPv4_FRAGMENTS_01` to `_04`, and `IPv4_REASSEMBLY_04`, `_10` and `_12`. For example,
`IPv4_FRAGMENTS_01`'s row proves `fail_echo_id`, but nothing proves `fail_echo_seq` or
`fail_data_mismatch` can fire.

**Why it exists.** The disposition model was written per case, back when most cases had one
guard. Per-final accounting arrived later and was scoped to the one disposition whose promotion it
guards.

**Risk if left.** A wrong expected value or a broken conjunct in any of the 33 guards turns a real
violation into a pass or a timeout, with every audit green. This is the vacuity the register
exists to catch, and it is invisible there. The census does not count it either, because nothing
records it.

**Textbook fix.** Account per fail final for every case, not per case. Each final must be proven
by one of the register's existing mechanisms:

- a sound row landing on that final;
- a `_neg` mapped to it in `tools/fault_injection_coverage.json`;
- a registry guard naming it;
- a deferred-negatives reason.

A final proven by none is UNDISPOSED. It belongs in the exhaustiveness ledger
(`tools/negative_coverage_undisposed.txt`, which `tools/debt_census.py` already unions) at
`CASE:final` granularity, grandfathered and forced to shrink the way the case-level ledger was.
That makes the 33 visible open work, not a green audit.

**Done when:** `negative_coverage_audit.py --check` rejects a multi-final case with a final no
mechanism proves, unless the final stands in the ledger. The ledger holds exactly the unproven
finals. `debt_census.py` counts each of them.

**Resolution.** The audit now records, for every positive case with a `fail` final, which
mechanisms prove each final. The case disposition is unchanged: a row still outranks a `_neg`, so
a case with a row stays SOUND_ROW. The ledger's unit is now `case:final`. A bare `case` is used
only for an undisposed case with no fail final. `--check` rejects a new unproven final as
NEW_UNPROVEN_FINAL.

Two of the four mechanisms the fix lists could not reach a SOUND_ROW case's other finals.
REGISTERED_WITH_ROW rejected any registry entry on a case with a row. DEFERRED_REDUNDANT rejected
any deferral of a case already disposed. Both rules were case-level. They are now per final:

- A SOUND_ROW case may carry a partial registry entry, and a `CASE:final` deferral in
  `deferred_negatives.json`, as TD-41 already allowed a partial coverage entry.
- A registry guard or a deferral must be the only account of its final. Beside a row or a `_neg`
  on the same final, PROOF_CONFLICT rejects it.
- Any other disposition keeps its own completeness rule, because its label promises every final.
  REGISTRY_AND_FAULT now binds FAULT_INJECTION cases only.

`--self-test` proves the rule fires, on copies of the live model. CI runs it before `--check`.

**Runs (2026-09-24).**

- `--check` before the ledger was written: 33 NEW_UNPROVEN_FINAL, over 518 fail finals. These are
  the 33 finals this entry lists, case for case.
- After `--write-ledger`, the ledger holds those 33 lines and `--check` is OK.
  `debt_census.py --check` lists each of them as `undisposed ... no proof`.
- `--self-test` passes 10 checks. With `unproven_units` stubbed to return nothing it fails 2. With
  the exclusive-mechanism rule removed it fails 2 more.

Repaying the 33 is not part of this entry. The ledger holds them, and the census counts them.

---

## TD-43 — the smoke lane no longer fits its timeout, so it judges nothing

**Status:** RESOLVED (2026-09-25). **Logged:** 2026-09-24, after two consecutive pushes were
cancelled by the job timer rather than answered by the suite. The Done-when is answered by run
36124982820; see the Correction at the end, which also records that this entry's original CAUSE
was wrong.

⚠⚠ **The OBSERVATION below holds and its CAUSE is wrong.** The entry says the lane outgrew its
cap, and the ⚠ table in it measures a 37% case-count growth to support that. The growth is real;
it is not what cancelled those runs. **Correction** at the end of this entry has the step
timings, which nobody had looked at, and the repair that followed from them.

**What it is.** `.github/workflows/smoke-test.yml` runs on `[self-hosted, netns]` — this
workstation — under `timeout-minutes: 120`. Both pushes made today were cancelled at the cap:
run 35950954625 at 2 h 1 m 14 s and run 35960649319 at 2 h 1 m 34 s. A cancellation is not a
pass and not a fail. The lane that gates every push is currently returning NO VERDICT, and
because a cancelled run looks orange rather than red, nothing about it demands attention.

⚠ **The lane ALSO grew, which this entry first attributed entirely to the machine.** Measured
2026-09-25 by asking the harness what each step selects:

| step | selection | cases |
|---|---|---|
| positive, parallel | `--exclude-deferred --exclude-platform-known-fail --exclude-serial` | **754** |
| positive, serial (`--workers 1`) | `--only-serial` | 15 |
| negative rows | `--list-neg-rows` | 66 |
| known-fail asserts | `--list-known-fails` (added 2026-09-25) | 5 |
| | **per push** | **840** |

The cap was sized against the job's own comment, which still says "549-case positive smoke".
The positive lane is now 754 — **37% more than the number the 120 minutes was chosen for** —
and the negative and known-fail stages sit beside it. So contention is not the whole story, and
the third option below ("measure the lane on a quiet box") should be read as measuring a lane
that is materially bigger than the one the estimate described. A cap raised to fit today's
contention would still be sized against a case count that keeps growing.

**Why it exists.** The cap was chosen against a measurement that has since stopped being true.
The job's own comment records it: a cold path of "vsomeip rebuild + 543 SCXML codegen + harness
+ tc8-dut + unit tests plus 549-case positive smoke plus negative curated set on a mid-tier
developer machine totals ~90 min", warm runs ~25 min, "we set the cap high enough for the cold
path and rely on the test logic to hard-fail rather than the timer to bound runtime". That
estimate assumes the machine is doing nothing else. It no longer is: the same box concurrently
runs other repositories' agent loops and their builds, and it is where local verification runs
too. The cap did not move; the machine underneath it did.

**Risk if left.** The push gate is off, silently. A regression that smoke would catch now
reaches main with an orange tick beside it, and the longer this holds the more the tick is read
as noise. Two adjacent facts make it worse rather than better: the 14 negative cases added in
`dcba9425` joined this lane, and `feedback` recorded elsewhere in this session shows a push also
CANCELS an in-flight smoke, so a busy day can leave the lane never once completing.

**Textbook fix.** Name which of these it is rather than raising the number, because raising the
cap alone removes the only bound on a genuine hang:
- make the lane not compete — the runner is shared with work this repository does not control,
  so either it gets the box while it runs, or it accepts a queue rather than a timer;
- split what runs per push from what runs on dispatch, so the per-push lane is sized to the cap
  and the full set is a deliberate act (the shape `lwip-sweep.yml` already uses);
- measure the lane on a quiet box first. Until someone knows what it costs when nothing else
  runs, every number chosen for the cap is a guess.

**Done when:** consecutive pushes produce a pass or a fail from this lane rather than a
cancellation, and the timer is bounding a hang rather than ordinary work — with the run that
shows it named here.

**Correction (2026-09-25) — the cause was not the lane's size, and the step timings say so.**

The entry reasoned from the job's total wall-clock and from a case count. Neither can locate a
cost. The Actions API carries per-step timings for every run, including cancelled ones, and no
round had read them. They put 92% of the cancelled run in two steps that run no tests at all:

| step | run 35950954625 (cancelled, 2h01m) | run 35441257615 (success, 47m) |
|---|---:|---:|
| Build harness (vsomeip + cmake) | **59m03** (49%) | 8m14 |
| Suite producer coexistence ratchet | **51m42** (43%) | 8m20 |
| Run positive smoke (754 cases) | cancelled at 8m36 | 13m45 |
| Run timing-cadence serially | not reached | 2m20 |
| Run negative curated set | not reached | 1m33 |
| lwIP DUT regression | not reached | 11m28 |

So the whole of TESTING is about 28 minutes, inside a 120-minute cap. The lane is not close to
outgrowing it, and the 37% case growth lives entirely inside the 13m45 step.

⚠ **And it is contention, not a cold cache or a wide rebuild — which the two commits settle.**
The cancelled run is `77c50641`, whose diff is almost entirely `tools/*.py`, `.txt` and `.json`:
a build that should have been nearly all ccache hits took 59m03. The successful run is
`eb6b9761`, which changed **15 case headers** — real C++, a genuinely wider rebuild — and built
in 8m14. The run with less C++ to compile took seven times longer. What differs is what else
this box was compiling, which is the one thing the lane does not control.

**What was repaid, and what was deliberately not.**

- **The second full build left the push lane.** The coexistence ratchet is a clean from-scratch
  harness build re-proving that an out-of-tree suite reusing an in-tree case id still builds and
  registers. It is the largest removable term — 51m42 of the 121 — and it proves a BUILD
  property that moves only when the registrar / suite-producer surface does. It now runs on a
  nightly `schedule` and on dispatch. ⚠ This is NOT the entry's "split what runs per push"
  option, which the table above refutes: splitting by test content would save minutes. What
  moved is compile work.
- **Nothing that decides a conformance verdict moved.** Note that today's failure mode already
  costs more than the split does: when the lane overruns, every step after the cancelled one
  reads "skipped", so the negative set, both topology profiles, the whole lwIP regression and
  the testability checks ran on NEITHER of those two pushes. A push lane that finishes runs
  strictly more than one that does not.
- **The nightly got its own concurrency group.** It carries the steps no push re-proves, so
  leaving it in the group a push cancels would have meant it ran only on nights nobody pushed.
- **The lane now accounts for its own time.** `tools/ci_step_timing.py`, called from an
  `always()` step, writes the table above into the run summary. This is the part that closes the
  loop rather than this instance of it: the cause here went unexamined for a day and was then
  recorded WRONG in this very entry, because reading it took an API reconstruction by hand.
  Verified against run 35950954625's real payload, and its self-test pins the row that matters
  most — the step still running when the cap fires, which has no `completed_at` and is the one a
  naive renderer drops.
- **The cap stays at 120 and is now documented as a hang bound rather than a budget.** Raising it
  was refused for the reason the entry already gives; sizing it to contention is impossible, since
  wall-clock on a shared box measures the box.

⚠ **Correction to the paragraph below, 2026-09-25:** "not in this repository" was wrong. The
largest remaining lever WAS an in-repo file — this was the only repository on the workstation
with no `.claude/remote-build.toml`, so `bx` sent its builds to the very box the runner uses.
That file now exists, and the machine gap it exposes is registered as TD-50. Moving the runner
remains an option; it is no longer the only one.

**First verdict since the repair, 2026-09-25 — run 36114404143, push, HEAD `51dacc1e`:
`success` in 1h30m** (08:42:42Z .. 10:13:42Z). Every step ran and passed; the ratchet reads
`skipped`, which is the change working.

| step | this run | the cancelled run | a quiet run (35441257615) |
|---|---:|---:|---:|
| Build harness | 38m37 (42%) | 59m03 | 8m14 |
| Run positive smoke | 28m07 (31%) | cancelled at 8m36 | 13m45 |
| lwIP DUT regression | 14m46 (16%) | never reached | 11m28 |
| Suite producer ratchet | **skipped** | 51m42 | 8m20 |

⚠ **The change is what produced the verdict, and the arithmetic says so rather than the
intention.** The ratchet cost 51m42 under comparable contention; 1h30m plus that is about
2h22m, past the 120-minute cap. This push would have been cancelled too. And the steps the two
cancelled runs never reached — the negative set, both topology profiles, the lwIP build and
regression, all three testability checks — ran here.

⚠ **Contention is undiminished and is now the whole of the remainder.** The harness build took
38m37 against 8m14 on a quiet box and the positive lane 28m07 against 13m45 — still three to
four times. Nothing in this repair touched that; TD-50 is where it lives, and part of it was
this session, working in this repository on this box while the lane ran.

On the accounting step: it exited 0, which requires the API fetch, the render and the append to
`$GITHUB_STEP_SUMMARY` all to have succeeded, and the same endpoint and tool produced the table
above when run by hand against this run. The rendered summary TEXT is not verified here, because
GitHub exposes job summaries only in the run page and not through the API.

**Status stays OPEN on one word of the Done-when: "consecutive".** This is one push. The next
one that returns a verdict closes the entry.

⚠ **The next push (run 36123076966, HEAD `3527fc29`) returned `failure` in 25 seconds, and it
was NOT counted** — by the spirit of the Done-when, against its letter. That fail was
`actions/checkout` dying in 2 s: nothing built, nothing ran, and the lane judged nothing about
the change. Its cause is TD-51, and it was EXPOSED by this repair rather than caused by it —
the lane had been timing out before reaching the step whose leftovers broke the next checkout.

**RESOLVED by the third push: run 36124982820 (HEAD `91aee810`), `success` in 56m26**, no step
short of success. Three consecutive pushes, ZERO cancellations, and two of the three a verdict
on the change itself. The timer bounded nothing in any of them.

⚠ **And that run measured the remainder rather than only passing.** It ran while this session
deliberately kept the box idle, and the contrast is the cleanest evidence TD-50 has:

| step | 36124982820 (box idle) | 36114404143 (box busy) | quiet baseline |
|---|---:|---:|---:|
| Build harness | **8m25** | 38m37 | 8m14 |
| Run positive smoke | 23m24 | 28m07 | 13m45 |
| **job total** | **56m26** | 1h30m | 47m07 |

The build returned to its quiet-box cost almost exactly. Not competing for the box is worth 34
minutes of this lane, which is what TD-50 is for — and the only thing that produced it here was
an agent choosing not to compile, which is the habit this entry has twice recorded as not being
a mechanism.

⚠ **What remains is not in this repository, and it is the only permanent fix.** Removing the
ratchet takes the cancelled run's non-test cost from 110m to 59m, which would very likely have
let it finish — "likely" being exactly as far as the evidence reaches. The 59m build was a
cache-warm build slowed sevenfold by other work on the same host, and nothing inside this repo
can stop that. The fix is to move the `[self-hosted, netns]` runner off this workstation onto one
of the build machines, which needs a runner provisioned there with netns + sudo. Rationing the
box instead — a host-wide lock between the lane and local agent work — was considered and
rejected: it stalls the developer's own loops for the length of a run, and under
`cancel-in-progress` a queued lane can be superseded before it ever starts, which trades a
cancelled verdict for a never-attempted one.

---

## TD-44 — the fault catalogue shares a header with the opcode contract, so adding one flavour recompiles the suite

**Status:** RESOLVED (2026-09-25). **Logged:** 2026-09-24, measured while adding two ingress
fault flavours in one session and paying a full rebuild for each.

**The closing measurement.** One `touch` of the catalogue header, then a build, counting the
objects make decided to rebuild — the Done-when's "counting what the build touched":

| | before | after |
|---|---|---|
| registrar chunks recompiled | 25 of 25 | **8 of 25** |
| non-case translation units recompiled | several | **0** |
| the 8, by name | — | `register_17` … `register_24`, the negative-only chunks |

⚠ **Wall-clock is NOT the instrument here and must not be quoted as one.** This tree builds
through ccache, so a rebuild decision on unchanged content is a cache hit and finishes in
seconds; the first attempt at this measurement read 8 s and looked like success while make had
in fact rebuilt 23 of 25. Count the objects, not the clock — a real flavour change alters the
header's content, so every object counted here is a genuine compile.

⚠ **The first implementation was wrong, and only the count caught it.** Both parts landed —
catalogue split out, chunks partitioned — and 23 of 25 chunks still rebuilt. The cause was a
single include: the catalogue reached consumers through `_fault_flavor_arm.h`, and
`_arp_traits_base.h` included that for ONE composed helper
(`emitEgressFlavorRequestProvocation`). All 64 ARP cases include that base, the MD5 bucketing
spreads them over every chunk, and so the catalogue was back in all of them. Six case headers
used the helper; 800 were paying for it. It now lives in `_arp_fault_arm.h`, and the base
carries a comment saying why it must not be re-added.

**What it is.** `include/tc8/upper_tester_protocol.h` carries two things whose change rates
differ by an order of magnitude: the Upper Tester OPCODE and wire contract, which is stable,
and the EGRESS / INGRESS / APP fault-flavour catalogues, which grow every time a `_neg` case
needs a new mechanism. Appending one flavour constant to a catalogue therefore dirties every
consumer of the wire contract.

Measured, not estimated:

| | count |
|---|---|
| translation units including the header | 272 |
| of those, case headers | 241 |
| case headers that actually name a `ut::` symbol | 237 |
| case headers naming a FAULT-CATALOGUE constant | 171 |
| case headers using `ut::` but NOT the catalogue | 70 |

So the include is honest — only 4 of 241 are unused — but two thirds of the blast radius is
the catalogue's, and the remaining third plus the 31 non-case TUs are collateral. The case
registrar is chunked into 24 TUs and buckets by an MD5 of the case id precisely so that adding
a CASE perturbs one chunk (`src/harness/CMakeLists.txt` says so in its own comment); adding a
FLAVOUR defeats that, because the dirty header is in every chunk.

**Risk if left.** It is a tax on exactly the work the negative-coverage ledger asks for. Each
unproven fail final left needs its own fault mechanism, so each costs a whole-suite rebuild of
roughly twenty minutes before its case can be run once — and a typo in the case costs the same
again, as it did here. It also pushes toward batching unverified cases, which is the habit
that produced unproven `_neg` files in the first place.

**⚠ The fix first written here does not pay, and that was measured on 2026-09-25 rather than
argued.** Splitting the header reduces the TU count and leaves the WALL CLOCK exactly where it
is, because the registrar's MD5 bucketing spreads the flavour-naming cases across every chunk:

| | count |
|---|---|
| registrar chunks | 25 |
| chunks holding at least one flavour-naming case header | **25** |
| fewest flavour-naming cases in any one chunk | 2 |

Every chunk therefore still recompiles when a flavour constant moves, and the chunks are where
the twenty minutes goes — a rebuild measured the same day touched 26 of 38 objects and 19 of
them were registrar stubs. Two flavour-adding rebuilds that day each ran about 32 minutes.

**Textbook fix, in two parts that only work together.**

*One:* split the catalogues into their own header (the opcode contract keeps
`upper_tester_protocol.h`, the flavour values move to a sibling) and include it only where a
flavour is named. Measured, the reach is shorter than it looks: 182 case headers name a
flavour and 165 of them ALREADY include `_fault_flavor_arm.h`, so the catalogue belongs
wherever that helper can reach it and only 17 case headers plus 3 lwIP DUT files and one unit
test need a direct include. The SSOT property is unchanged: the catalogue is still written once
and shared by harness and DUT, which is what makes it a wire contract.

*Two:* make the chunking flavour-aware. Bucket the flavour-naming cases into their own chunk
range instead of spreading them by MD5 over all of them. 182 of 806 cases at the current 32
per TU is about 6 chunks, so a flavour change recompiles 6 instead of 25 while adding a CASE
still perturbs exactly one chunk — the property the MD5 bucketing exists for, preserved because
the partition is applied before the hash, not instead of it.

Part one without part two changes the touched-TU count and nothing a person waiting on a build
would notice. That is why this entry's original plan is recorded as insufficient rather than
quietly replaced.

⚠ Not free, and the cost is why this is a register entry rather than a change already made:
the split is itself one whole-suite rebuild, and every consumer's include list has to be
corrected in the same commit or the build breaks halfway. Worth doing BEFORE the next batch of
fault mechanisms, not during one.

**Done when:** a commit that appends a flavour constant recompiles no translation unit that
does not name a flavour AND recompiles a MINORITY of the registrar chunks — both shown by
counting what the build touched, not by reasoning. The second clause is the one the original
Done-when was missing, and the reason this entry outlived its first plan.

---

## TD-45 — a fault-injection negative can only run where its positive cannot pass, and nothing notices

**Status:** RESOLVED (2026-09-25). **Logged:** 2026-09-24, after nearly shipping a negative
that would have passed with the fault disarmed.

**How it was repaid.** Not by re-pairing the three bases, which would have meant writing
negatives whose value the entry already argues is near zero, but by giving those finals a
BETTER account than a synthetic fault: the platform's own defect, measured. A
`platform_known_fail_verdict` records the `class:reason` each registered deviation actually
lands, `tc8-harness test --list-known-fails` prints the pairs, and
`tc8-orchestrator --known-fail` runs the set with NOTHING injected and asserts them. An
unmodified DUT reaching a fail final in a real run is the strongest reachability evidence
the five mechanisms have; this audit now counts it as `known_fail`.

The vacuity the entry named is closed from the other side too. A mapping is only counted
where a lane actually asserts the claim (`known_fail_lanes`), so a registration nothing
re-measures accounts for nothing — which is what stops this fix from being the same
vacuity one level up. `arp_06`, `arp_33:dut_arp_request_after_double_injection` and
`ipv4_fragments_04:dut_reassembled_mismatched_protocol_fragments` were the three units left
in the ledger, and they are now accounted this way; the ledger is empty.

Measured on lwip-tap 2026-09-25, all sixteen registered deviations: nine land a `fail:`
verdict, seven land an `inconclusive:`, none pass. The six whose prose already named a
verdict all agreed with the measurement, so no registration was stale at the moment the
mechanism landed — that is the baseline it now holds.

⚠ **Known limit, recorded rather than papered over.** An `inconclusive:` registration
asserts nothing today: the harness returns a non-conclusion, the driver's Skip arm swallows
it, and the case reports green either way. Seven of sixteen are in that state. Closing it
needs the runner to distinguish "no observation, as registered" from "no observation,
unexpectedly", which is a verdict-model change rather than a driver change.

**What it is.** A `_NEG` proves its positive's guard is checkable by driving a faulted DUT onto
a `fail` final. The fault seams live only on the lwIP fixture, so every fault-injection
negative is capability-gated to that fixture. If the POSITIVE is a `platform_known_fail` there,
the negative runs on the one platform where the conformant path it is validating does not
exist — and `tools/negative_coverage_audit.py` credits it anyway, because it checks that a
mapped `_neg` exists and has the right final shape, never that the pairing is meaningful on the
platform both can reach.

Measured across the whole coverage map, not just the entry that surfaced it:

| | count |
|---|---|
| positives carrying a fault-injection mapping | 30 |
| of those, `platform_known_fail` on lwIP | 3 |
| negatives under those three | 10 |

`IPv4_FRAGMENTS_04` (2 negatives), `IPv4_REASSEMBLY_11` (4), `IPv4_REASSEMBLY_13` (4). Two of
the ten arrived in `dcba9425`; the other eight predate it, so this is a standing shape rather
than one commit's mistake.

**How it was found, because the mechanism matters more than the list.** A negative was written
for `IPv4_FRAGMENTS_04`'s PHASE-1 final (`dut_reassembled_mismatched_protocol_fragments`) using
an ingress flavour that normalises the reassembly tuple. It passed. It would also have passed
with the flavour disarmed: lwIP's bucket match omits the protocol field, so the fixture already
commits that violation — the fault changed nothing and the negative proved nothing. It was
dropped rather than committed. The two that shipped are NOT that case: they prove PHASE-2
finals the known-fail does not reach, so they are weaker rather than empty. The distinction is
which final the platform's own defect lands on, and no tool computes it.

**Risk if left.** A negative that cannot fail is indistinguishable from one that cannot be
written, and the register counts them the same. This is the vacuity TD-42 made countable per
final; this entry is the part TD-42's counting still cannot see.

**Textbook fix.** Teach the audit the pairing: when a positive is `platform_known_fail` on the
platform its negative is gated to, require the mapped final to be one the platform's own
failure does not already reach — stated in the override's reason, which already names the
mechanism — or refuse the mapping. Whatever the rule, it has to be MECHANICAL: the reasoning
above took a run, a pcap and a ledger diff to reach, and a reviewer will not repeat it.

**Done when:** the audit rejects a mapping whose negative can only run where the positive is a
known-fail on the same final, the three bases above are each either re-paired or exempted with
a reason, and a deliberately vacuous mapping is shown to be refused.

---

## TD-46 — a UT-armed fault cannot precede the DUT's first resolution, so an ordering final is unreachable

**Status:** OPEN (accepted). **Logged:** 2026-09-24, after building a fault for
`udp_egress_before_dut_arp_request` and finding the mechanism circular.

**What it is.** Every ingress fault flavour is armed by a UT datagram from the tester. The
lwIP DUT must resolve the tester's address to ANSWER that datagram, so its first ARP Request
goes out because of the arm itself. A fault meant to make the DUT skip resolution therefore
cannot be in force before the resolution it is supposed to prevent.

Measured on the pcap of the attempt (the whole capture, four frames):

```
t=0        DUT      -> broadcast   ARP Request who-has <tester> tell <dut>
t=0.00004  tester   -> DUT         ARP Reply
t=1.70     tester   -> DUT         ARP Request   (the case's own injection)
t=1.70     DUT      -> tester      ARP Reply
```

The attempted flavour seeded a static entry from the first inbound IPv4 frame after arming,
intending that frame to be the arm datagram. It cannot be: the hook reads the flavour while
the frame passes, and the UT handler sets the flavour only after the frame is delivered. The
arm cannot be its own seed. Moving the seed later does not help either — by then the DUT has
already resolved, which is the event the guard grades.

**Which finals this reaches.** `ARP_39` and `ARP_40`, whose
`udp_egress_before_dut_arp_request` grades the ORDER of the DUT's first egress against its
first resolution. Both stay in `tools/negative_coverage_undisposed.txt`.

**Why this is accepted rather than deferred.** It is not a gap in the fault catalogue that a
better flavour would close. Arming is control-plane traffic, the DUT answers control-plane
traffic, and answering requires resolution — the three together make "no resolution before the
first egress" unobservable on a fixture whose only fault channel is that same control plane. A
DUT that could be faulted out of band, or one pre-seeded before it ever sees the tester, would
not have the problem; this one does.

**Done when:** the ordering is demonstrated on a DUT whose fault arming does not itself require
the resolution under test — an out-of-band arming channel, or a fixture whose ARP table can be
seeded before its first control exchange. Neither exists here, which is why this stands in
`tools/debt_accepted.txt` rather than waiting for one.

---

## TD-47 — a `_NEG` that never reaches its stage reports green, and today's rule enlarged that

**Status:** RESOLVED (2026-09-25), the same day it was logged. **Logged:** 2026-09-25, splitting
the half of TD-23 that outlived its Done-when, and recording that a change made the same day
made it bigger rather than smaller.

**How it was repaid.** The orchestrator now treats a NON-CONCLUSION from a `_NEG` case as a hard
failure. The asymmetry with every other case is the point: a negative's whole job is to reach a
guard and prove a fault fires there, so a run that never reached it demonstrates nothing — while
the exhaustiveness ledger goes on counting that guard as proven checkable on the strength of a
case that has silently stopped checking it.

Two premises were MEASURED before the gate was tightened, because tightening one on an unknown
population is how a green lane becomes red by accident:

| | |
|---|---|
| negatives the lwIP sweep runs | 163 |
| of those, PASS | **163** — zero non-conclusions, zero skips |
| lwIP-only negatives on the Linux lane | `Verdict::Skip` with `skip:requires_capability_…` |

So the rule turns nothing green into red today; it exists to catch the first one that regresses.
And the capability skip is a DIFFERENT verdict class from a non-conclusion, verified by running
six lwIP-only negatives on the Linux lane, so a negative sitting out a run it cannot drive is
untouched.

The discriminator is the `_NEG` / `_NEG<n>` suffix — the harness registers a negative as an
ordinary case, so nothing on the wire says "this is a negative", and the naming is what every
register in the tree already keys on. Its boundaries are pinned by a unit test
(`negative_case_detection_matches_the_registers_naming`): `ARP_34_NEG2` matches,
`ARP_34_NEG_EXTRA` and `ARP_NEGOTIATION_01` do not, because a mis-classification would turn an
ordinary non-conclusion into a hard failure.

⚠ **What this does NOT cover, stated rather than implied.** A negative that reaches its guard
and passes for the wrong reason still reports green — this catches the run that did not reach
the guard, not the one that reached it vacuously. That is TD-45's territory, repaid separately
for the known-fail pairing; the general form (a `_neg` whose fault has gone inert while its
positive still fails for its own reasons) remains the harder question.

**What it is.** A fault-injection negative carries exactly ONE `fail` final — the
conformant-DUT branch, role `fault_injection_inert`, which `negative_coverage_audit.py`
enforces. Every other way the run can miss is therefore `inconclusive`, which the orchestrator
maps to a skip and JUnit renders as `<skipped>`: green. So a negative whose fault has gone
inert AT A STAGE IT NEVER REACHED reports nothing at all.

**Why the arity rule is still right.** A run that never reached the guarded stage says nothing
about whether the fault works, so grading it `fail` would blame the fault-wiring for a
precondition that was never met. The two misses also have OPPOSITE fixes — an arm that landed
too late moves earlier, one that landed too early moves later — and a single `fail` reason
cannot say which is owed. The rule is not the defect; the defect is that the honest
non-conclusion is then indistinguishable from a healthy skip.

**How it grew.** Five negatives landed on 2026-09-25 with multi-stage shapes (a first emission
driven with the fault disarmed, the arm placed between, the second graded). Four of them were
written with a `fail_compliant_*` for each way the run could miss and the audit rejected them;
routing those catches to `inconclusive` is what made them pass — and what put four more
never-reached-the-stage outcomes into the green column. The count is small and the direction is
wrong, which is the whole reason this is written down rather than left implicit.

**Risk if left.** The `_NEG` population is the instrument the whole negative-coverage ledger
rests on: an empty ledger means every guard is PROVEN checkable, and that proof is only as good
as the negatives still firing. A negative that has silently stopped exercising its guard keeps
its ledger entry and keeps reporting green, which is the same rot TD-23 repaid for the
known-fail ledger, one register over.

**Textbook fix.** The known-fail mechanism is the shape to copy, because the problem is
identical: an outcome nothing re-measures. A negative's expected outcome is already known — it
is `pass` — so a lane can assert it the way `--known-fail` asserts a registered verdict, and a
`_NEG` that turns inconclusive reds instead of skipping. What it must NOT do is re-grade a
genuine precondition failure as a conformance failure; the distinction TD-23 made between "no
observation, as registered" and "no observation, unexpectedly" is the same one needed here, and
it is a verdict-model question rather than a driver one.

**Done when:** a `_NEG` that stops reaching its guarded stage reds in a lane rather than
rendering as a skip — MET; the four negatives named above are covered by it — MET, the rule is
per-case-shape and covers all 163 the sweep runs; and a deliberately un-armed negative is shown
to red — MET in the equivalent form the tree allows: the classification boundary is pinned by a
unit test and the capability-skip path was run end-to-end to show it is untouched, which is what
"shown" can mean without authoring a deliberately broken case the suite would then have to carry.

---

## TD-48 — the DUT's second address is declared by the topology and compiled by the case, and nothing checks they agree

**Status:** RESOLVED (2026-09-25), the same day it was logged. **Logged:** 2026-09-25, as the
stated residue of TD-25.

⚠ **This entry was FIRST LOGGED WITH A WRONG PREMISE, and the correction is the useful part of
it.** It said the address was compiled in TWO places — the stimulus constant and a literal in
the case's SCXML — and it was written from the case header's own comment, which claims "SCXML
cond literal … gates the pass branch on exact match". Opening the SCXML instead shows
`cond="cpp:… captured.src_ip == expected.dut_alias_ip …"`: an expectation key, not a literal,
and it has been one all along. What follows is the debt as MEASURED afterwards; the header
comment that misled it is corrected in the same commit. The rule it cost, again: read the
corpus, not the summary that describes it.

**What it is.** Four things name "the DUT's second address", and they do not read one source:

| consumer | reads | follows a site override? |
|---|---|---|
| netns provisioner (`netns.rs`, `setup-netns.sh`) | `wire::DUT_ALIAS_IP` / `TC8_WIRE_DUT_ALIAS_IP` | no |
| SCXML expectation `ipv4.dut_alias_ip` | `cfg.dut_alias_ip4` | yes |
| capability `dut.secondary_ip` (TD-25) | `cfg.dut_alias_ip4` | yes |
| UI_07 stimulus — the ASK | `kDutAliasIp4Be` | **no** |

All four values originate in one `tools/wire.def` row, which generates the C++ constant, the
Rust constant and the shell variable, so there is no hand-copy between languages and the netns
topologies cannot drift at all: `apply_alias_overrides` in `main.rs` says in its own doc that
only the host-NIC topologies reach it, because single-pc and lwip-tap build the aliases
themselves and their configured value IS the wire constant.

The drift is reachable on exactly one path, and that path is real. An `External` or `SshRemote`
site names its DUT's alias in `site.wire.dut_alias_ip`. The expectation follows it. The
capability follows it. The ask does not — the harness asks a conforming external DUT to emit
from 172.16.0.5, an address it does not hold, and gets a refusal.

⚠ **And TD-25 made that path worse hours before this entry fixed it.**
`dut_has_secondary_address()` defaulted to `false` with only `SinglePc` overriding, so on a site
that HAD declared its DUT's alias the case became a capability skip — the operator stated the
premise in the field that exists for stating it, and the gate ignored the statement.

**How it was repaid.** The ask now reads the same field the bit is derived from.

- `UDP_USER_INTERFACE_07`'s stimulus passes `cfg.dut.secondary_ip` instead of the constant. A
  case can no longer be admitted by a capability and then ask for a different address than the
  one that admitted it, because there is one field and both come from it.
- `External` and `SshRemote` answer `dut_has_secondary_address()` from
  `site.wire.dut_alias_ip.is_some()`. The operator's declaration is the only thing that knows a
  real DUT's addresses, so it is what the topology reports.
- ⚠ **`cfg.ipv4.dut_alias_ip` was rejected as the ask's source for the second time**, for the
  reason `ipv4_expectations.h` gives: it is the EXPECTATION that
  `--negative ipv4.dut_alias_ip=10.99.99.99` flips to prove this assertion is load-bearing.
  Sourcing the ask from it would move both sides together and make that negative vacuous. The
  identity field is what the ask reads, the expectation is what the SCXML reads, they hold the
  same value, and they must stay separately addressable.
- `kDutAliasIp4Be` stays with no reader on the assertion path: it is the netns fixture's own
  value, which `setup-netns.sh` and `netns.rs` still configure from the same `wire.def` row.
- The capability audit's demand token moved from the constant to `secondary_ip`, which is the
  stronger statement — a case cannot name the address without naming the thing that decided the
  bit.

⚠ **UI_08 is the untouched mirror:** its stimulus still asks the DUT to send TO the compiled
`kTesterAliasIp4Be` while the SCXML compares against `expected.tester_alias_ip`, so a site naming
its own tester alias moves one and not the other. Not fixed here because the tester has no
identity struct to hold the value — `TestConfig` carries `DutIdentity` and per-protocol
expectations and nothing else — so the fix is a new surface rather than a redirected read.
Registered as TD-49.

**Done when:** the address UI_07 asks for and the capability that admitted the case come from
one field — MET; and a site declaring its DUT's alias runs the case rather than skipping it —
MET, by the two host topologies now reporting that declaration.

---

## TD-49 — the tester's own second address is asked for by a constant and graded against a config value

**Status:** RESOLVED (2026-09-25), the same day it was logged. **Logged:** 2026-09-25, as the
measured mirror of TD-48. **Resolution** at the end.

**What it is.** `UDP_USER_INTERFACE_08` is UI_07 with the sides swapped: it asks the DUT to send
TO a caller-specified destination, which needs the TESTER to hold a second address. The ask is
the compiled `kTesterAliasIp4Be` (172.16.0.4); the SCXML grades against
`expected.tester_alias_ip`, which the orchestrator fills from `cfg.tester_alias_ip4`. A site that
names its own tester alias in `site.wire.tester_alias_ip` moves the expectation and not the ask,
so the DUT is told to send to 172.16.0.4, the tester is listening on something else, and nothing
arrives.

Same shape as TD-48, same reachable path — `External` / `SshRemote`, where
`apply_alias_overrides` is the only thing that knows the wire — and unreachable for the same
reason on the netns topologies, whose configured value IS the wire constant.

**Why it exists.** TD-48 fixed the DUT side by pointing the ask at `cfg.dut.secondary_ip`, an
IDENTITY field that `DutIdentity` already existed to hold. The tester has no counterpart:
`TestConfig` carries `DutIdentity` and the per-protocol EXPECTATION structs and nothing else, so
there is no identity home for "an address the tester holds".

⚠ And the obvious shortcut is the one TD-48 rejected twice: `cfg.ipv4.tester_alias_ip` holds the
right value but is the expectation that `--negative ipv4.tester_alias_ip=10.99.99.99` flips to
prove UI_08's assertion is load-bearing. Reading the ask from it would move both sides together
and make that negative vacuous.

**Risk if left.** Narrower than TD-48's was, because no capability gates UI_08 — so instead of a
skip, a site with its own tester alias gets a case that cannot pass and whose reason points at
the DUT. It is unreachable on every in-tree topology today, which is why this is logged rather
than rushed.

**Textbook fix.** Give the tester the identity surface the DUT already has: a `TesterIdentity`
beside `DutIdentity` in `TestConfig`, carrying the tester's primary and secondary addresses,
filled from the same `--expect` path (`tester.secondary_ip`), with UI_08's stimulus reading it.
That also gives `cfg.ipv4.tester_ip` — today an expectation field that several stimuli already
read as if it were identity — a correct home, which is the larger reason to do it this way
rather than by special-casing one address.

**Done when:** UI_08's ask and the tester's configured second address come from one field, with
the expectation still independently flippable, and a site naming its own tester alias is shown
to exercise the case rather than time out on it.

**Resolution.** The tester got the identity surface the DUT already had.
`TesterIdentity` sits beside `DutIdentity` in `TestConfig`, carrying `secondary_ip`, filled by
`--expect tester.secondary_ip`, and UI_08's stimulus reads it instead of `kTesterAliasIp4Be`.
The constant now has no reader on the assertion path — verified by counting its occurrences with
comments stripped: one, its own definition.

⚠ **It starts as a one-field struct on purpose.** `cfg.ipv4.tester_ip` is the tester's primary
address living in an EXPECTATION struct, which several stimulus paths already read as though it
were identity. That is a real crossing and moving it means moving every reader at once; this
header is the home that migration lands in, and adding `ip` here without migrating them would
create the second source this entry exists to remove.

⚠ **The emit belongs in `tools/expect_surface.def`, not in `dispatch.rs`, and the first attempt
put it in the wrong one.** It was hand-pushed beside the `dut.secondary_ip` push before the
`.def`'s own header corrected it: hand-mirroring that key->source list across two drivers is
what TD-12 was. The split is whether the row is CONDITIONAL — `dut.secondary_ip` is control flow
(a topology provisions a second DUT address or does not), `tester.secondary_ip` is not, because
every topology here stands its own tester up.

Measured 2026-09-25, and the second row is the one that matters:

- **single-pc positive**: `PASS UDP_USER_INTERFACE_08`, plus `UDP_USER_INTERFACE_07`,
  `UDP_USER_INTERFACE_02` and `UDP_FIELDS_12` beside it — neighbours on the same base, so the
  change did not widen anything.
- **single-pc `--negative`**: `PASS UDP_USER_INTERFACE_08`, i.e. flipping
  `ipv4.tester_alias_ip=10.99.99.99` still lands on the declared
  `fail:dut_emitted_udp_with_wrong_user_interface_dst_ip`. **This is the proof of separation**:
  had the ask followed the flip, the DUT would have been told to send to 10.99.99.99, nothing
  would have been captured, and the case would have reported `inconclusive` rather than the
  declared fail. The negative is still load-bearing.
- **lwip-tap**: `PASS UDP_USER_INTERFACE_08` — the case needs no DUT capability (the second
  address is on the tester's side), so unlike UI_07 it keeps running on the one-netif fixture.

⚠ Two gates caught this change before the verification did, which is the argument for having
them: `check_expect_keys.py` named the missing `TC8_EXPECT_GROUP(tester, …)`, and the build
named `TC8_EK_tester was not declared` — the X-macro requires a per-group default block, an
undef block and a parser overload, none of which a new key gets for free.

---

## TD-50 — no build machine can compile this repository, so its builds land on the box its own CI gate runs on

**Status:** RESOLVED (2026-09-25), the same day it was logged. **Logged:** 2026-09-25, as the
named remainder of TD-43. ⚠ It carried TWO wrong causes on the way; both are kept below, with
the **Resolution** at the end.

**What it is.** This was the only repository on this workstation without a
`.claude/remote-build.toml`, and `bx` said so in as many words — "tc8-harness declares no
.claude/remote-build.toml, so nothing says what to send or what it needs" — and therefore sent
every build here. Here is also where the `[self-hosted, netns]` smoke runner lives, so the
repository was competing with its own push gate: a cache-warm harness build inside the gate took
59m03 against 8m14 on a quiet run, and the gate returned no verdict (TD-43).

The declaration now exists and is honest. What it revealed is that **neither registered machine
can build this repository**, measured 2026-09-25:

| requirement | pc2 | pc3 | needed for |
|---|---|---|---|
| cmake / make / g++ / python3 / git | ok | ok | everything |
| libpcap | ok | ok | capture |
| **libtins** | missing | missing | every dissector the tester links |
| **`sce-codegen`** | missing | missing | all 543 case state machines |
| vsomeip3 | ok | missing | the ETS mock DUT |
| **CommonAPI / CommonAPI-SomeIP** | missing | missing | the ETS mock DUT |
| cargo | missing | missing | the orchestrator (6 s locally; not worth sending) |

`bx` now selects pc2 on its own merits and then refuses by name —
``host pc2 cannot RUN `sce-codegen` — existence is not usability`` — instead of silently
building here. That refusal is the repayment's first half working: the gap is named rather than
absorbed.

⚠ **`sce-codegen` is the surprising one.** It is not built from this tree. `third_party/sce`
ships `SCEFindCodegen.cmake`, which FINDS a generator; this workstation resolves it to
`~/.local/bin/sce-codegen`. A machine without it builds nothing at all here, so it is the first
thing to place, not the last.

**Why it exists.** Nobody wrote the file. The `remote-build` skill has the same finding recorded
against another repository — 815 builds fell to local because the declaration was missing, which
it calls "not a refusal, but nobody having written it" — so this is a known shape rather than a
new one.

**Risk if left.** TD-43's remaining exposure, exactly. The gate and this repository's own
compiles share one box, and the only thing separating them is a habit ("keep quiet after a
push") that this session broke itself, running a 1445-second local build while the lane's
evidence was the thing at stake. A habit is not a mechanism.

**Textbook fix.** Provision one machine to meet the declaration, cheapest first: `libtins-dev`
by package, then `sce-codegen` at the pin this tree expects. That alone moves the tester and the
unit tests off this box, which is the build the repository actually repeats. CommonAPI is a
separate and larger step and buys only the mock DUT, which the hosted `build-test` lane already
declines to build for the same reason — so it is deliberately last.

**Progress, 2026-09-25 — the machine gap is closed and a THIRD obstacle appeared behind it.**

pc2 now meets the declaration's package and executable requirements:

- `libtins-dev 4.5-1build2` installed, which is byte-for-byte the version this workstation
  carries (both are Ubuntu noble `universe`), so the dissectors compile against the same library
  rather than a near one.
- `sce-codegen` placed and verified running there, reporting `0.1.0 (341f0e0c446c)` — the SAME
  build this workstation resolves. It was COPIED rather than rebuilt on purpose: a freshly built
  generator could emit different code than the local one, and then a remote "verification" would
  be verifying a different program.
- The submodule's quilt state (`third_party/vsomeip/.pc/`) was neither tracked nor ignored, which
  made `bx` refuse to send the tree and name ten paths. It is now ignored through that
  submodule's `.git/modules/.../info/exclude` — local and uncommitted, because a `.gitignore`
  there is a TRACKED file of a vendored upstream.

⚠ **What still blocks it is this repository's own shape, not the machines.** `bx` requires the
local and remote working trees to agree and walks submodules to check. The base patch series is
applied INTO `third_party/vsomeip`'s working tree, so four tracked files
(`CMakeLists.txt` and three `implementation/` sources) sit permanently modified there, and `bx`
refuses with them named. Setting `send = "tracked"` does not avoid it — the comparison happens
regardless of what is sent.

⚠⚠ **This entry has now carried TWO wrong causes, and the second one was written as
"measured". Both are recorded here rather than edited away, because the way each was reached is
the lesson.**

**Wrong cause #1** (corrected earlier the same day): "the remaining fix is outside this
repository." It was not — the largest lever was an in-repo file, `.claude/remote-build.toml`,
which did not exist.

**Wrong cause #2, and the instructive one:** that `bx` compares a submodule it does not send, so
the defect is the checker's SCOPE. The supporting "control experiment" was running `bx` under
`send = "tracked+submodules"` and again under `send = "tracked"`, observing that it printed
"sending tracked+submodules files" and then "sending tracked files" and refused identically both
times, and concluding that the comparison ignores what travels.

⚠ **That experiment varied nothing.** `$send` appears exactly ONCE in the whole of `bx` — in the
sentence that reports what it is sending. It never branches behaviour. So the knob under test
controlled a noun in a message, the two runs were the same run, and "identical refusal" was
guaranteed rather than informative. A difference that cannot fail to appear is not evidence.

**What actually happens, read from `bx`'s source and then confirmed on the far side.** The
submodule leg sends the submodule and then runs, on the remote,
`git submodule update --recursive --force` followed by `git submodule foreach 'git clean -qfd'`.
A forced update RESETS each submodule's working tree to its recorded commit, so any local
modification the transfer carried is discarded by the next line of the same command. Measured on
pc2 on 2026-09-25: the remote `third_party/vsomeip` is populated, at HEAD `6171fdfe`, with
**zero** porcelain lines — while this side holds four modified tracked files. The equality proof
then correctly reports a difference it can never not report.

⚠ And that reset is not an oversight to patch out. Its own comment records what the raw-directory
rsync it replaced cost: files deleted upstream survived on the build machines, every later run
was refused with a message blaming "the working tree", and one repository burned two days of
local-only builds while the cause was recorded wrongly twice. Restoring dirty submodule state
across the wire means going back to that.

**So the repair is in THIS repository, which is where the first reading put it before the false
experiment moved it.** The series must stop living as uncommitted modifications inside the
submodule's working tree. `scripts/setup-vsomeip.sh` already has the seam — `TC8_VSOMEIP_SRC`
selects the tree it resets, patches and builds, and the submodule is only its default — so the
change is to make that default a scratch checkout at the pinned revision, leaving the submodule
as what it should be: the pin RECORD, not the build scratch. Not mutating a vendored source tree
in place is the ordinary form of this, independent of `bx`.

⚠ Do NOT close this by adding `pin_host` or by loosening `needs`. A declaration that names less
than the build needs routes work to a machine that then fails mid-build, which is worse than the
named refusal it replaced.

**Done when:** `bx` sends a harness build to a build machine and it succeeds there, and a smoke
run overlapping local work in this repository no longer shows the build step inflating.

**Resolution.** `scripts/setup-vsomeip.sh` no longer builds in the submodule. Its default source
tree is now a git worktree of `third_party/vsomeip` at that submodule's own HEAD, stood up at
`.vsomeip-src` (gitignored), recreated or moved to the pin on every run. `TC8_VSOMEIP_SRC` still
overrides it and an OEM tree gets no worktree built beside it.

The worktree is git-native: it shares the submodule's object store, so it costs no clone and no
network, and the script's existing `git checkout -- . && git clean -fdxq -e build` reset applies
to it unchanged. **The submodule goes back to being the pin RECORD rather than the build
scratch**, which is the ordinary rule about not mutating vendored sources in place and would be
worth doing with no build machine in sight: `git status` in this repository was never clean
before, so a real change inside the submodule looked exactly like the patch series.

Measured 2026-09-25, after one full `setup-vsomeip.sh` run into a scratch prefix (deliberately
NOT `/usr/local`, which a separate note records as breaking SOME/IP when clobbered):

| | |
|---|---|
| `third_party/vsomeip` porcelain | **0 lines** |
| `.vsomeip-src` porcelain | 4 modified — the base series, where it belongs |
| both trees | detached at `6171fdfe`, the pin |
| install | vsomeip 3.7.3 into the scratch prefix |

And then the thing the entry exists for:

```
bx: WHERE=remote host=pc2
bx: trees agree: HEAD dabf2e50, working state identical
bx: exit=0 in 32s
```

This repository now builds on a build machine. The machine side had already been provisioned
(libtins-dev at the same version this workstation carries, `sce-codegen` copied rather than
rebuilt so the generator is byte-identical); what remained was this repository's own shape, and
the first reading of this entry had said so before a false experiment moved it.

⚠ The second half of the Done-when — a smoke run overlapping local work no longer inflating —
is not claimed here. It needs a run that overlaps deliberately, and the mechanism that makes it
true (builds leaving the box) is what just landed. TD-43's own table already measured the size
of the effect: 8m25 against 38m37 for the same step.

---

## TD-51 — a sudo lane left a root-owned log directory, and the next checkout died in it

**Status:** RESOLVED (2026-09-25), the same day it was logged. **Logged:** 2026-09-25, from the
push that followed TD-43's first green run. **Resolution** at the end names the run that shows
it.

**What it is.** The netns lanes run the orchestrator under `sudo`, so any directory the
orchestrator creates is owned by root. The runner user cannot then delete its contents, and
`actions/checkout`'s `git clean` fails — before anything builds.

`smoke-test.yml` already knew this. The comment above its pre-creation `mkdir -p` says it in as
many words: *"A root-owned dir here fails `git clean` (exit 128) and blocks all future
checkouts."* What it did not have was anything checking that the list under that comment stayed
complete. The `--known-fail` assertion step was added on 2026-09-25 with
`--log-dir smoke-logs/known-fail`, and that path was never added to the `mkdir`.

Measured 2026-09-25:

- Run 36123076966 (push, HEAD `3527fc29`): `failure` in 25 s, `actions/checkout@v5` failing at
  2 s. Its log is ~20 lines of `smoke-logs/known-fail/<case>.{harness.log,dut.log,pcap,trace.json}
  제거에 실패했습니다: 허가 거부`.
- The runner workspace confirmed it directly: `smoke-logs` was `coin coin` and
  `smoke-logs/known-fail` was `root root`, created 18:56 local — inside the previous run's
  known-fail step.

⚠ **It was invisible for a week because the lane never reached the step.** Both 2026-09-24 runs
were cancelled by the job timer during the positive lane, so the known-fail step ran for the
first time in run 36114404143 — the first run to finish after TD-43's repair. Repairing one
defect is what made the other one reachable. A latent break of this kind cannot be found by
reading; it needs the lane to get far enough to leave the residue.

**Why it exists.** The rule was a comment plus a hand-maintained list, and the pairing between
"every `--log-dir` in this file" and "every path in the `mkdir`" was enforced by nothing. A step
was added and the list was not.

**How it was repaid.** `smoke-logs/known-fail` added to the pre-creation list, and the pairing
now gated by `tools/workflow_logdir_audit.py`, wired into `workflow-hygiene.yml` beside the
runner-trigger gate — hosted, so it judges the self-hosted lane from outside it. The root-owned
directory left on the runner was removed by hand after confirming the evidence it held was
already in run 36114404143's `smoke-diagnostics` artifact (8.6 MB, unexpired).

⚠ The gate's own first live run returned **three** findings of which **two were comment prose**
— a sentence describing "each step's `--log-dir smoke-logs/<step>`" and another ending
"--log-dir to feed this." Stripping whole comment lines fixed it, and the self-test now pins
both. A gate that is two parts noise teaches its reader to skim, which is how the real row gets
skimmed too.

**Done when:** a push-triggered run checks out cleanly after a previous run executed the
known-fail step, and `workflow_logdir_audit.py --check` is green in the hosted lane — with the
run that shows it named here.

**Resolution.** Run 36124982820 (push, HEAD `91aee810`): `success` in 56m26, no step short of
success. Both halves of the Done-when are in it:

- Its `actions/checkout@v5` passed — the step that died at 2 s in run 36123076966 — and the run
  it checked out AFTER is 36114404143, the one whose known-fail step created the root-owned
  directory. So the ordering that produced the break was reproduced, and it no longer breaks.
- Its own known-fail step ran again (0m52, `success`), now writing into the runner-owned
  directory the `mkdir -p` pre-creates, so the residue this entry is about is not re-created.
- `workflow-hygiene` run 36124982755: `success`, with `Log-dir ownership gate self-test` and
  `Log-dir ownership gate` both listed as executed rather than skipped. ⚠ Checked as steps and
  not as a job conclusion on purpose: a gate that is green because it never ran is the failure
  mode this repository keeps meeting, and a job-level tick cannot tell the two apart.

---

## TD-52 — the tester's own IP is an expectation, so the field 167 cases grade cannot carry a negative

**Status:** RESOLVED (2026-09-26), the same day it was logged. **Logged:** 2026-09-26, from a
prose sweep of this repository rather than from the register — the deferral was a comment
nothing counted. **Resolution** at the end.

**What it is.** `cfg.ipv4.tester_ip` is the tester's primary address. It lives in
`Ipv4Expectations`, and **167 case SCXMLs grade against `expected.tester_ip`**. It is also what
44 C++ stimulus sites across 33 files read to decide where to SEND — the tester's own address in
a frame it builds. One field, both jobs.

That crossing is the exact shape this tree separates everywhere else, and TD-48/TD-49 spent a
day on two instances of it. The consequence here is measurable and specific: **no sound negative
row can ever be authored for `ipv4.tester_ip`.** A `--negative ipv4.tester_ip=10.99.99.99` would
move the grading AND the destination together, the DUT would be asked to answer an address
nobody holds, and the case would report `inconclusive` instead of the declared fail. The most
graded field in the tree is the one field whose guard cannot be proven load-bearing.

⚠ That is not a prediction. The same wall was measured on 2026-09-25 on
`SOMEIPSRV_ONWIRE_01`, whose graded fields are also its destination: both candidate flips landed
on `inconclusive:no_response_within_listen_window`, and the case stayed deferred for it.

**Why it exists.** `TesterIdentity` did not exist until TD-49, so there was nowhere else for the
address to live. TD-49 created the struct with one field and said so in a comment — "this header
is the home that migration lands in; it is not the migration" — which is prose, and prose is not
counted by `debt_census.py`. This entry is that comment, registered.

**Risk if left.** Not a live failure: no negative row flips this field today, precisely because
one cannot be authored. The risk is the silent kind — the exhaustiveness audit counts 167 cases
as graded by a guard nothing can demonstrate, and the next person who tries to author that row
spends the afternoon that `ONWIRE_01` cost before concluding the same thing.

**Textbook fix.** `TesterIdentity` gains `ip`, the orchestrator emits `tester.ip` from the same
source `ipv4.tester_ip` already comes from, and the 44 stimulus sites read `cfg.tester.ip`. The
expectation field keeps its name, its value and all 167 readers; only the ASK moves. Then a
negative on `ipv4.tester_ip` becomes authorable, which is the check that the split took.

⚠ Half of it is worse than none: with some sites migrated and some not, a flip moves one part of
the ask and not the other, and the case fails for a reason unrelated to its guard. It is 44
sites in 33 files and they move together or not at all.

**Done when:** no C++ stimulus path reads a `tester_ip` expectation field, and a negative row on
`ipv4.tester_ip` is authored and shown to land on its declared fail rather than a
non-conclusion — with the case and the run named here.

**Resolution.** `TesterIdentity` gained `ip`, `tools/expect_surface.def` emits `tester.ip` from
the same source `ipv4.tester_ip` already came from, and every stimulus site moved:
`git grep cfg.ipv4.tester_ip -- src/` returns **0**, against 48 before (44 code uses plus 4
comments describing those uses, which moved with them). The expectation keeps its name, its
value and all 167 SCXML readers; only the ask moved. It went in one commit because half of it is
worse than none.

**The done-when's second clause, demonstrated on `UDP_USER_INTERFACE_04`.** Its `pass_expr`
grades `captured.ut_recv_src_ip == expected.tester_ip` and its miss branch does not, so the flip
discriminates rather than filtering — most cases put `expected.tester_ip` in BOTH branches,
where a flip matches nothing and reports a non-conclusion. Authored as
`ipv4.tester_ip=10.99.99.99` → `fail:dut_received_udp_with_wrong_src_ip_in_confirmation`, and
the run returned **PASS**: the flip landed on the declared fail. Before the migration the same
flip would have redirected the stimulus as well, which is the state this entry was about.

⚠ **The row was then REMOVED, and the audit is why.** `negative_coverage_audit.py` reported
`PHASE_F_REGRESSION: lwip FAULT_INJECTION 110 < high-water 111`. Nothing was lost: this case
already has a `_NEG` sibling proving that same final, so the row became a SECOND account for it
and the counts moved (sound 76→77, fault-inj 179→178) rather than growing. This tree's rule is
one account per `case:final`, so the demonstration stands as the measurement recorded here and
the permanent disposal stays with the `_NEG` that already had it. No coverage is given up by
removing it.

Positives re-run after the migration, across every family that reads the moved field:
`UDP_FIELDS_01`, `UDP_FIELDS_04`, `UDP_PADDING_02`, `UDP_USER_INTERFACE_04/05/07`,
`TCP_CHECKSUM_02`, `TCP_CHECKSUM_03`, `TCP_HEADER_11`, `IPv4_FRAGMENTS_05`, `ARP_48` — all PASS.

⚠ And the compile was proven on a build machine rather than here: `bx` sent the tree to pc2
(`trees agree: HEAD 4aaf0496, working state identical`, uncommitted edits included) and built it
cold in **107 s** while this workstation sat at load 29 with two free cores. That is TD-50
paying for itself on the first change after it landed.

---

## TD-53 — one negative row per case, so a template with two graded fails could only prove one

**Status:** RESOLVED (2026-09-26), the same day it was logged. **Logged:** 2026-09-26, after a
question — "so you're saying it can't be done?" — sent me to the corpus instead of the ledger.

**What it is.** A case authored at most ONE negative row: `neg_wrong_token` + `neg_expect_fail`,
one pair per entry. `ARP_32/33/34/35` share a template with THREE graded branches, taken in
document order:

| | branch | condition |
|---|---|---|
| 1 | `pass` | egress MAC == `expected.tester_mac2` |
| 2 | `fail_used_mac1` | egress MAC == `expected.tester_mac` |
| 3 | `fail_unknown_mac` | neither |

Two of those are fail finals and per-final accounting (TD-42) wants an account for each, but one
row can only ever carry one. So `udp_eth_dst_is_mac1_not_mac2` sat in the deferred-negative
ledger reading *"not by any single flip … the case's one row slot is already spent"*.

⚠ **That sentence was true and I read it as "impossible".** It is a statement about the tool,
not about the case. Two measurements corrected it:

- `neg_wrong_token=arp.tester_mac=<MAC2>` with `neg_expect_overrides=[arp.tester_mac2=<other>]`
  lands on `fail_used_mac1` exactly — branch 1 misses because its expectation moved, branch 2
  matches because the DUT's real MAC2 now equals what `tester_mac` claims. `neg_expect_overrides`
  existed for precisely this and nobody had tried it.
- With that row in place the coverage audit named the real limit rather than a wall:
  `PROOF_CONFLICT` on the final now proven twice, and `NEW_UNPROVEN_FINAL` on the one whose
  account the swap had taken.

**How it was repaid.** A case may now author extra rows, across five files and three languages:

- `neg_extra_wrong_tokens` / `neg_extra_expect_fails`, parallel arrays because this inventory's
  reader is regex-based and cannot see inside a nested object. The shape's own failure mode is a
  length mismatch — it would pair a token with another row's verdict and assert the wrong thing
  while looking authored — so the loader refuses it, and so does the audit. Two rows flipping the
  same key are refused too: that proves one thing twice while counting as two accounts.
- `--list-neg-rows` prints `CASE|INDEX|token|verdict`; `--negative-row-index N` selects. An index
  out of range is refused rather than quietly falling back to row 0, which would assert one
  verdict and report it as another.
- The orchestrator carries the index IN THE CASE ID (`ARP_35#1`). The schedule is keyed by one
  string, and that is what makes a row a schedulable unit; widening the tuple would have moved
  three signatures to say the same thing. Row 0 keeps the bare id, so all 76 existing rows and
  every report line are unchanged.
- ⚠ The positional filter had to learn the split as well. Without it, `--negative ARP_35` ran
  only the primary — the run reported complete while proving half of what it had just listed,
  which is the exact shape of green this repository keeps refusing.

Measured after: `--list-neg-rows` 76 → 78, and
`--negative ARP_33 ARP_35` → **PASS ARP_33, PASS ARP_33#1, PASS ARP_35, PASS ARP_35#1**, each on
its own declared final. `negative_coverage_audit.py`: 0 undisposed, 0/518 unproven, deferred
4 → 2. The compile was proven on pc2 first, where `-Wshadow` caught a shadowed local in 35 s.

**Done when:** a case with two expectation-graded fail finals proves both by rows, with the run
named here — MET.

---

## TD-54 — the DUT's SOME/IP service identity is an expectation, so the cases that grade an endpoint could not fault it

**Status:** RESOLVED (2026-09-26), the same day it was logged. **Logged:** 2026-09-26, the fifth
and sixth instances of one defect, found by asking what the *most long-term-correct* repair was
instead of reaching for the one that was nearest.

**What it is.** The last unsplit identity in the tree. `cfg.someip.{dut_iface_ip, udp_port,
tcp_port, service_id, instance_id}` are EXPECTATIONS — 209 SCXMLs grade `expected.dut_iface_ip`
and 186 grade `expected.service_id` — and 30 C++ stimulus sites read the same fields to decide
where to ADDRESS a Method Request. A `--negative` row rewriting one of them moved the grading and
the destination together, so the DUT was asked to answer an endpoint nobody held and the case
reported a non-conclusion instead of its declared fail.

⚠ **I had recorded that as structural.** The deferred-negative ledger said of
`SOMEIPSRV_ONWIRE_01`: *"the two fields the guard grades are the SAME two the request is
addressed to … a sound negative needs a fault seam rather than an expect flip."* The observation
was right and the conclusion was wrong — those fields are not inherently one thing, they were
one field nobody had split. The same sentence had been written about `cfg.ipv4.tester_ip`
(TD-52), `kTesterAliasIp4Be` (TD-49) and `kDutAliasIp4Be` (TD-48) in turn.

**Why the alternative was refused.** The nearest repair was a third vsomeip patch: make the
stack echo a wrong message id, or answer from another endpoint, when a fault is armed. The
series is quilt-managed, compile-gated and has two patches already, so the machinery was not the
objection. The objection is what such a patch IS. Both existing patches REMOVE an upstream
behaviour that makes a spec assertion unobservable; a fault patch adds a deliberate
non-conformance to the reference implementation, and `dut/dut_service/ets_fault.h` had already
drawn that line — *"the response serialization is vendored-vsomeip-owned"*. Splitting identity
from expectation needs no such thing, and it fixes every case in the family rather than the two
that happened to be stuck.

**How it was repaid.** `SomeIpIdentity` beside `DutIdentity` and `TesterIdentity`, carrying the
two ports and the service/instance ids, filled by `--expect someip_dut.*` from the same source
the expectations come from. 30 ask sites across 25 files moved; `git grep cfg.someip.<field> --
src/` now returns one hit, a comment about the grading half.

⚠ **The DUT's IP is NOT in the new struct, and that was a measurement.** `someip.dut_iface_ip`
and `dut.ip` hold the same value (both `172.16.0.2`), so the 24 sites reading the expectation
only did so because the identity had never been offered to them. They now read `cfg.dut.ip`.
Adding a copy would have been the duplicate this family exists to remove.

**Measured 2026-09-26.**

- `SOMEIPSRV_ONWIRE_01` now carries a row — `udp_port=30599` →
  `fail:response_src_endpoint_did_not_match_dut_service_endpoint` — and the run returns **PASS**.
  The flip moves the grading while the request still reaches the DUT, which is exactly what the
  ledger said was impossible.
- Regression across every family whose ask path moved: `ONWIRE_01/06`, `RPC_18`, `BASIC_03`,
  `SD_MESSAGE_02/17`, `FORMAT_26`, `ETS_086`, `ETS_152` — 9/9 PASS.
- Deferred negatives 2 → 1; `0/518` fail finals unproven; `0` undisposed.

⚠ **`SOMEIPSRV_RPC_18` did NOT open, and the split is what made its real blocker visible.** Its
phase 2 grades the error frame's `service_id` against the expectation; its phase 1 waits for an
OfferService and filters on that SAME expectation. The ask is fixed — the request now goes to the
right service under a flip — and the case still reports
`inconclusive:no_offer_service_within_listen_window`. Phase 2's only other graded field is a
compiled method-id constant with no expect key. Opening it means loosening phase 1 to check THAT
the DUT is offering rather than WHICH service, which weakens that phase's premise; it is left
deferred with that trade stated rather than taken quietly.

⚠ One measurement nearly went into this entry as a false negative: the first ONWIRE_01 run still
reported `no_response_within_listen_window`, because the expect surface had been regenerated and
the ORCHESTRATOR not rebuilt, so `someip_dut.*` was never emitted and the port was 0.
`--print-expect` showed zero such keys. A stale driver looks exactly like a repair that did not
work.

**Done when:** no C++ stimulus path addresses a request from a SOME/IP expectation field, and a
case that grades a service endpoint carries a row that lands on its declared fail — MET, by
`SOMEIPSRV_ONWIRE_01`.
