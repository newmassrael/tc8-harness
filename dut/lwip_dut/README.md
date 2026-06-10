# lwIP DUT fixture

Runs the [lwIP](https://savannah.nongnu.org/projects/lwip/) unix-port
stack on a host tap interface as a persistent `--topology external` DUT.
This is the project's second DUT platform after the Linux reference DUT
(`dut/dut_service/tc8-dut`), and the first strict-embedded-stack
consumer of the per-platform `inventory_overrides.json` mechanism.

The fixture exists for two reasons:

1. **Harness portability proof** — every verdict difference against the
   single-pc Linux baseline must be explainable from the DUT stack
   alone, not from harness assumptions about Linux.
2. **A second deviation ledger** — lwIP's RFC deviations differ from
   Linux's; comparing the two `platform_known_fail` sets shows which
   TC8 assertions discriminate between real-world stacks.

## Sweep result (2026-06-10, lwIP master, 116 UT-independent cases)

Categories swept: ARP (41), ICMPv4 (14), IPv4 core (30), UDP (31).
SOME/IP, TCP, DHCPv4 and IPv4-autoconf categories need either a SOME/IP
application or Upper Tester opcodes on the DUT and were out of scope for
the first sweep.

| Bucket | Count | Cases |
|---|---|---|
| Meaningful PASS | 53 | ARP responder/drop set, ICMPv4 echo + errors, IPv4 header/checksum/TTL/version, fragments, reassembly (with the lwipopts alignment below), `UDP_INTRODUCTION_03` |
| Vacuous PASS | 2 | `ARP_03`, `ARP_05` — absence assertions whose egress provocation is inert on this fixture (see below); excluded from the regression list so green cannot be mistaken for coverage |
| lwIP stack deviation (`platform_known_fail`) | 6 | `ICMPv4_TYPE_11/_12`, `ICMPv4_ERROR_02`, `IPv4_FRAGMENTS_04`, `IPv4_REASSEMBLY_11`, `IPv4_REASSEMBLY_13` |
| Blocked: no SOME/IP responder | 24 | `ARP_03..15`, `ARP_22/28`, `ARP_32..35`, `ARP_38/39/40`, `ARP_48/49` (egress-provocation cases, incl. the two vacuous passes) |
| Blocked: Upper Tester not yet ported | 33 | `IPv4_ADDRESSING_01/02`, `IPv4_FRAGMENTS_05`, all swept `UDP_*` failures |

## Verified lwIP deviations

Each entry was confirmed against lwIP source, not inferred from the
verdict alone. Pcaps for every claim are reproducible with
`--log-dir` on the sweep command below.

- **`ICMPv4_TYPE_11/_12` — ICMP Timestamp not implemented.**
  `src/core/ipv4/icmp.c` counts `ICMP_TS` in MIB2 stats and falls
  through to "type not supported"; no Timestamp Reply path exists.
  Not option-fixable.
- **`ICMPv4_ERROR_02` — ICMP Parameter Problem never emitted.**
  lwIP only generates Destination Unreachable and Time Exceeded
  (`icmp_dest_unreach` / `icmp_time_exceeded`). The Linux reference
  DUT carries the same known-fail for a different reason (pointer
  semantics), so this assertion currently discriminates strict-RFC
  stacks from both fixtures.
- **`IPv4_FRAGMENTS_04` — reassembly bucket match omits the protocol
  field.** `IP_ADDRESSES_AND_ID_MATCH` in `src/core/ipv4/ip4_frag.c`
  compares (src, dst, id) where RFC 791 §3.2 requires the
  (src, dst, protocol, id) quad, so fragments of different protocols
  merge into one bucket and reassemble. Fixable only by patching lwIP.
- **`IPv4_REASSEMBLY_11` — static reassembly timer ignores TTL.**
  lwIP ages buckets by the compile-time `IP_REASS_MAXAGE` tick count;
  RFC 791 §3.2's `MAX(TLB, TTL)` timer extension is not implemented
  (same deviation class as Linux's static `ipfrag_time`, which makes
  this case the Linux fixture's known-fail as well).
- **`IPv4_REASSEMBLY_13` — overlap reassembly structurally
  unsupported.** With the default `IP_REASS_CHECK_OVERLAP=1` lwIP
  throws overlapping fragments away; verified that disabling the check
  does not help because chain validation requires exact
  `prev->end == next->start` contiguity, so an overlapped bucket never
  completes and times out (pcap shows the ICMP "ip reassembly time
  exceeded" emission). RFC 791's most-recent-wins example procedure
  would need a reassembly rewrite.

## Required lwipopts.h alignment

- `IP_REASS_MAXAGE 2` — the harness fixes `<ipIniReassembleTimeout>`
  at 3 s (mirroring the Linux fixture's per-case `ipfrag_time=3`
  conditioning). lwIP's `ip_reass_tmr()` ticks once per second and an
  entry survives `(MAXAGE, MAXAGE+1]` seconds depending on tick phase,
  so `MAXAGE=2` bounds the bucket lifetime to <= 3 s
  (`IPv4_REASSEMBLY_10` phase B probes at ~3.03 s) while keeping the
  phase-A 1 s window valid. The lwIP default of 15 s fails
  `IPv4_REASSEMBLY_10`; lowering it flips `IPv4_REASSEMBLY_11` into
  the known-fail set above — the static timer can satisfy one of the
  two cases, never both.
- Defaults that already conform and must not be changed:
  `LWIP_BROADCAST_PING=0`, `LWIP_MULTICAST_PING=0` (broadcast Echo
  silence per `ICMPv4_TYPE_04/_05`), `IP_REASS_CHECK_OVERLAP=1`.

## Inert provocations (why the SOME/IP-blocked bucket exists)

ARP egress cases provoke a DUT-originated unicast UDP datagram with a
SOME/IP SubscribeEventgroup, expecting the Nack reply that the vsomeip
reference DUT produces. The lwIP fixture runs no SOME/IP application,
so the DUT never attempts the egress: positive cases fail with
`no_arp_request_within_listen_window` /
`no_udp_from_dut_within_listen_window`, and absence-assertions
(`ARP_03/_05`) pass vacuously. Opening this bucket requires either a
minimal SOME/IP subscribe-responder in the fixture app or a
harness-side egress-provocation abstraction; both are tracked as
follow-ups, and until then the cases are `expected:false` here so
`--vs-spec` against this file reports them as honest gaps.

## Running the sweep

```sh
sudo -n dut/env/smoke-test.sh \
  --topology external \
  --topology-conf dut/env/topology.d/examples/lwip-tap-fixture.conf \
  $(./build/tc8-harness test --list-cases \
      --inventory-overrides dut/lwip_dut/inventory_overrides.json \
      --exclude-deferred --exclude-platform-known-fail \
    | awk '/^  (ARP|ICMPv4|IPv4|UDP)_/{print $1}')
```
