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
`src/sce_integration/someip_sd_wire.def` (X-macro form). Every fixed-offset SD
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
`src/sce_integration/wire_read.h` (`::tc8::wire::readBe`) so both `.def` consumers
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

**Status:** OPEN (accepted, low priority). **Logged:** 2026-07-01 (cold review of TD-05).

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

**Why deferred.** The clean fix reaches into the verdict-path `udp_captured.h`, which
is out of TD-05's scope (the site-decoder elimination). Tracked here so the UT offset
mirror is not forgotten; the drift is low and the exporter output is gated
(`decode_pcap_golden`).

---

## TD-07 — SOME/IP-SD message magic (service 0xFFFF / method 0x8100) has no named SSOT

**Status:** OPEN (accepted, low priority). **Logged:** 2026-07-01 (cold review of TD-05).

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

**Why deferred.** A cross-cutting SSOT unification spanning the verdict path, the
builder, and the cases — broader than TD-05's site-decoder scope. Logged so the
scatter is visible.

---

## TD-08 — decode-pcap protocol-presentation tables live in the CLI translation unit

**Status:** OPEN (accepted, low priority). **Logged:** 2026-07-01 (cold review of TD-05).

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

**Why deferred.** A restructure with no behavior change; the command-local form is
defensible while there is a single consumer. Logged for the day a second text renderer
lands.

---

## TD-09 — decode-pcap has minor, accepted display divergences from the retired Python decoder

**Status:** OPEN (accepted, low priority). **Logged:** 2026-07-01 (cold review of TD-05).

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
label it truncated. **Why deferred:** each is a low-value behavior tweak (one needs a
verdict-struct change for a doc summary), so they are batched here rather than chased
piecemeal.
