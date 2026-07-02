# Tech-debt register

Known, accepted technical debt in tc8-harness. Each entry records WHAT the debt
is, WHY it exists, the RISK if left, the textbook FIX, and why it is DEFERRED.
This is a deliberate-deferral log, not a TODO list for unfinished features —
every item here is a working compromise with a documented escape path.

Entry format: a `## TD-NN` heading, then the fields below. Append new entries;
do not renumber. Reference an entry from code with a one-line pointer comment
(`see docs/tech-debt.md TD-NN`) at each coupled site so an editor of one site
discovers the others.

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
  if any (dispatch.rs / smoke-test.sh / dut_identity.py) emits a key absent from the
  registry — i.e. a key the generated consumer would silently drop.

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
emission. That residual is covered by per-scenario test design plus the runtime
`dut/env/parity-check.sh` (which diffs the actual emitted key sets) and
`config_test.rs`, not by this schema.

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

**Status:** OPEN (accepted, low priority). **Logged:** 2026-07-01 (cold-review residual).

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

**Status:** OPEN (accepted). **Logged:** 2026-07-01 (added with the extra_expect channel).

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

**Status:** OPEN (accepted). **Logged:** 2026-07-01 (surfaced by the tester_ipv4 drift).

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
`EventfdWaker` in `dut/dut_service/posix_socket_backend.cpp`) — used by the testability
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

**Status:** RESOLVED (2026-07-03 — verdict: NO, real middleware does not reject on major
mismatch). **Logged:** 2026-07-02 (session-correlation seam for the client reaction path).

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
