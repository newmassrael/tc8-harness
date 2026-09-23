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

**Status:** OPEN (accepted; not reachable in a shipped build). **Logged:** 2026-09-18, from a
consumer report of a build registering an injected suite alongside the in-tree one; verified
in-tree at `8fb3c671`.

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

**Status:** OPEN. **Logged:** 2026-09-23, re-measuring Tier-2 seam adoption at HEAD.

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

**Status:** OPEN. **Logged:** 2026-09-23, after two capability-declaration passes (TD-19 and
the ARP pass before it) each found the gap by hand.

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
gates `pre-commit` and `build-test.yml`, and it is green with no ratchet entries beyond the
ones argued in the file itself.

---

## TD-23 — an excluded case is never observed again, so both exclusion ledgers can only rot

**Status:** OPEN. **Logged:** 2026-09-23.

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

**Status:** OPEN. **Logged:** 2026-09-23, from the pcap of the one TCP non-conclusion left in
the lwIP sweep (346 of 348 pass, zero failures).

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

**Textbook fix.** Two independent halves. Answer the retransmission: the crafted SYN+ACK
should be re-sent for each matching SYN on that quad for as long as the phase is live, which
is what a real peer does and what makes phase 1 terminate promptly. And make the starvation
observable rather than inferred — a phase that never opened its own window should say so, in
the `tc8::UnperformedStimulus` vocabulary that already exists for "this did not happen", not
report an absence as if the DUT had been asked.

**Done when:** the harness answers a repeated SYN on a live phase quad, `TCP_UNACCEPTABLE_08`
passes on both the lwIP fixture and the Linux reference, and a phase whose window never opened
reports that fact instead of a DUT-shaped absence reason.

---

## TD-25 — the lwIP fixture has one address, and the case that needs a second one reports as a non-conclusion

**Status:** OPEN. **Logged:** 2026-09-23, the other non-conclusion in the same sweep.

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

**Done when:** a run of the lwIP sweep reports zero non-conclusions for this case — because it
passes, because the gate skipped it on a declared capability, or because the ledger no longer
offers it — and `dut/lwip_dut/sweep-cases.sh` again emits only what the fixture can pass.

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

**Status:** OPEN. **Logged:** 2026-09-24, while making `IPv4_REASSEMBLY_11` and `_13`
conclude.

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

**Status:** OPEN. **Logged:** 2026-09-24. Found 2026-09-18 while judging a consumer's cross-suite
case-alias request, recorded then only outside this repository, and re-verified in-tree at
`b324d50f`.

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

---

## TD-38 — the inventory axes resolve by case id alone, so a same-id case in another suite inherits them

**Status:** OPEN. **Logged:** 2026-09-24, found and re-verified as TD-37.

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
