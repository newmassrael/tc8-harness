# lwIP DUT fixture

Runs the [lwIP](https://savannah.nongnu.org/projects/lwip/) unix-port
stack on a host tap interface as a persistent `--topology external` DUT,
with an Upper Tester (UDP 30600) implemented on the lwIP socket API.
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

## Build

```sh
git clone --depth 1 https://github.com/lwip-tcpip/lwip.git /tmp/lwip
cmake -S dut/lwip_dut -B build-lwip-dut -DLWIP_DIR=/tmp/lwip \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build-lwip-dut -j4
```

The lwIP core is compiled by this directory's CMakeLists against
`dut/lwip_dut/lwipopts.h`, so the stack configuration cannot drift from
what the binary links.

## Sweep result (2026-06-10, lwIP master 8e75a40a, 232 cases)

Two sweeps against the final fixture: 116 UT-independent cases
(ARP / ICMPv4 / IPv4 core / UDP) and the 116-case TCP corpus opened by
the UT port (opcodes 0x03..0x0B + OpPing).

| Bucket | Count | Notes |
|---|---|---|
| Meaningful PASS | 153 | 53 non-TCP + 100 TCP |
| Vacuous PASS | 2 | `ARP_03/_05` — absence assertions whose SOME/IP egress provocation is inert here; excluded from the regression list |
| lwIP stack deviation (`platform_known_fail`) | 18 | 6 non-TCP + 12 TCP, each verified against lwIP source and/or pcap (below) |
| Blocked: no SOME/IP responder | 24 | ARP egress-provocation cases (includes the two vacuous passes) |
| Blocked: UT opcode not yet ported | 37 | 33 non-TCP (0x01/0x02/0x14) + 4 TCP (`TCP_RETRANSMISSION_TO_03/_04/_08/_09`, 0x13 OpQueryTcpInfo) |

`dut/lwip_dut/inventory_overrides.json` is the machine-readable single
source of truth for the last two buckets plus the deviation set; this
table is a dated report.

## Verified lwIP deviations

Each entry was confirmed against lwIP source or the wire, never
inferred from the verdict alone. Sweep pcaps are reproducible with
`--log-dir`.

Non-TCP:

- **`ICMPv4_TYPE_11/_12` — ICMP Timestamp not implemented.**
  `src/core/ipv4/icmp.c` counts `ICMP_TS` in MIB2 stats and falls
  through to "type not supported".
- **`ICMPv4_ERROR_02` — ICMP Parameter Problem never emitted.** Only
  dest-unreachable and time-exceeded generators exist. (The Linux DUT
  carries the same known-fail for pointer-semantics reasons.)
- **`IPv4_FRAGMENTS_04` — reassembly bucket match omits the protocol
  field.** `IP_ADDRESSES_AND_ID_MATCH` compares (src, dst, id); RFC 791
  §3.2 requires the (src, dst, protocol, id) quad.
- **`IPv4_REASSEMBLY_11` — static reassembly timer ignores TTL**
  (RFC 791 §3.2 `MAX(TLB, TTL)` not implemented; same deviation class
  as Linux).
- **`IPv4_REASSEMBLY_13` — overlap reassembly structurally
  unsupported.** Chain validation requires exact
  `prev->end == next->start` contiguity, so an overlapped bucket never
  completes regardless of `IP_REASS_CHECK_OVERLAP`.

TCP:

- **`TCP_BASICS_17` — simultaneous open not implemented.** A SYN
  arriving in SYN-SENT produces no SYN+ACK (RFC 793 p32).
- **`TCP_FLAGS_INVALID_06` — RST instead of discard** for an acceptable
  bare ACK in SYN-SENT (RFC 793 p66; Linux silently drops).
- **`TCP_FLAGS_INVALID_07` — no challenge ACK** for an OTW-SEQ SYN in
  SYN-RCVD (RFC 793 §3.9).
- **`TCP_ACKNOWLEDGEMENT_03` / `TCP_SEQUENCE_05` — delayed ACK
  coalescing.** lwIP's RFC 1122 §4.2.3.2-conformant ~250 ms delayed ACK
  falls outside per-segment observation windows tuned to Linux
  quickack; in `_03` the case's follow-up close converts the pending
  ACK into RST-on-close.
- **`TCP_URGENT_PTR_04` — urgent/OOB path not implemented** (RFC 793
  §3.7). The UT answers `OpReceiveTcpDataOob` with zero bytes by
  design, loudly logged.
- **`TCP_PROBING_WINDOWS_03/_04/_05/_06` — persist-timer probe shape
  and cadence.** lwIP's zero-window probe is a 1-byte new-data segment
  on its own persist schedule (first probe ~1.4 s); the matchers and
  windows are tuned to the Linux probe shape. The wire shows
  RFC 1122-conformant probing — harness-matcher widening candidates.
- **`TCP_RETRANSMISSION_TO_05/_06` — SYN RTO backoff shape.** The
  observation windows are shaped for the conditioned Linux fixture's
  linear SYN RTO; lwIP's RFC 6298 exponential backoff exits them.
  Test-design concern, mirrors the `TCP_UNACCEPTABLE_08` precedent.

## lwipopts.h alignment (why each non-default option exists)

Every entry carries its rationale in `lwipopts.h`; the
behaviour-shaping ones:

- `IP_REASS_MAXAGE 2` — harness fixes `<ipIniReassembleTimeout>` at 3 s;
  lwIP buckets live `(MAXAGE, MAXAGE+1]` s. The lwIP default 15 s fails
  `IPv4_REASSEMBLY_10`; lowering it flips `_11` into the known-fail set
  (the static timer cannot satisfy both).
- `LWIP_TCP_RTO_TIME 1000` — RFC 6298 §2.1 initial RTO SHOULD be 1 s
  (lwIP default is 3 s). More conformant, not a test accommodation.
- `TCP_MSL 30000` — TIME-WAIT = 2*MSL = 60 s, the value Linux hardcodes
  and `TCP_BASICS_11/_12` probe after.
- `LWIP_TCP_TIMESTAMPS 1` — RFC 7323; makes tester-side TIME-WAIT
  reopening deterministic when multi-phase cases reuse port quads
  (seq-only comparison against a random ISN is a coin flip).
- `LWIP_HOOK_TCP_ISN` + contrib `tcp_isn` addon — RFC 6528 ISN
  randomisation, seeded from `getrandom` in `main`. lwIP's default ISN
  is a near-constant tick counter: a security non-conformance, and the
  predictability kept colliding with tester-side TIME-WAIT remnants.
- `ARP_QUEUEING 1` — the per-case respawn means the first UT exchange
  of every case runs on an empty ARP cache; the default single-packet
  pending queue dropped the UT response in favour of the SYN the same
  RPC triggered.
- `SO_REUSE 1`, `LWIP_SO_LINGER 1`, `LWIP_SO_RCVTIMEO/SNDTIMEO 1`,
  `MEMP_NUM_NETCONN 16` — UT server requirements (listener rebinds over
  TIME-WAIT, ABORT primitive, bounded receive/send, socket pool).
- Defaults that already conform and must not change:
  `LWIP_BROADCAST_PING=0`, `LWIP_MULTICAST_PING=0`,
  `IP_REASS_CHECK_OVERLAP=1`.

## Upper Tester implementation notes (`lwip_ut_server.cpp`)

- Opcode surface: `OpOpenTcpSocket`..`OpReceiveTcpDataOob`
  (0x03..0x0B) + `OpPing` (0x15). `OpPing` reports `max_opcode` 0x0B —
  the top of the contiguous TCP block; the one-byte capability field
  cannot express a sparse set.
- `OpQueryTcpEstablished` answers from accept()/connect() completion
  (lwIP's socket layer exposes no TCP_INFO equivalent); the acceptor
  polls at 200 ms so the answer trails the wire by at most one tick.
- The spec ABORT primitive (`OpAbortTcpSocket`) calls `tcp_abort()` on
  the raw pcb under the core lock: lwIP's `SO_LINGER{on,0}` close only
  aborts when unsent/unacked data remains (`api_msg.c`), an empty queue
  always closes gracefully with FIN. This is the fixture's one
  dependency on a private lwIP header (`lwip/priv/sockets_priv.h`).
- Socket ids are monotonic from process start, exactly like the Linux
  tc8-dut — multi-phase cases rely on phase 2 getting sid 2. The
  per-case fresh-id expectation is satisfied by the fixture respawning
  the DUT per case (see below), never by resetting the counter.

## Fixture topology notes (`lwip-tap-fixture.conf`)

- **Per-case DUT respawn** (`topology_stop_dut` override): case stimuli
  hardcode the socket ids a freshly spawned DUT hands out, and passing
  cases legitimately leave auxiliary sockets open. Respawning restores
  the per-case fresh-DUT semantics the Linux fixture gets from
  `TOPOLOGY_SUPPORTS_DUT_SPAWN=1`.
- **Tester socket-state reset** (`ss -K dst <DUT_IP>` per case): the
  host-kernel analog of single-pc's per-case netns; clears tester-side
  TIME-WAIT sockets that would otherwise swallow the next case's SYN on
  a reused port quad.
- Stimulus-suppression iptables leaks from killed prior runs are
  handled by smoke-test.sh flushing the harness-owned `tc8-stimulus`
  chain at bring-up — no fixture-side rule knowledge.

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
    | awk '/^  (ARP|ICMPv4|IPv4|UDP|TCP)_/{print $1}')
```
