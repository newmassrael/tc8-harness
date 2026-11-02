# DUT control seam — one case, any backend

## Goal

The harness drives a real ECU through the standard AUTOSAR Testability
protocol (PRS_TPSP; wire SSOT `include/tc8/testability_protocol.h`), and an OEM
runs the standard cases by configuration alone, with no code. A case therefore
talks to the DUT only through a backend-neutral seam
(`src/sce_integration/include/sce_integration/dut_control.h`,
`dut_socket_control.h`). The backend is chosen once per run by `--dut-control`:

| Backend | Talks to | Surface |
|---|---|---|
| `opcode` (default) | the reference tc8-dut's private Upper Tester (UDP 30600) | a TC8-specific superset |
| `testability` | any DUT serving AUTOSAR Testability (UDP 30700) | the portable standard subset |

The choice is global, not per case: every case of a run drives the same DUT.

## What the seam exposes: protocol operations, split by capability

The seam's operations are protocol-level: connect, accept, send and close a TCP
connection, send a UDP datagram, and so on. Each backend implements them with
its own wire (an opcode request, or a Testability service primitive such as
CREATE_AND_BIND + CONNECT). An active open carries a `BindSpec`, so a case
that pins the DUT's source port can still say so through the standard
primitives.

The operations are grouped into sub-interfaces by capability (`ITcpControl`,
`IUdpControl`, `ITcpStateQuery`, `ITcpInfoProbe`, `ITcpRecvOob`, `IDhcpClientControl`,
`ILinkLocalControl`, `IUdpReceiveControl`, `IArpCacheAging`, `IArpStaticEntry`). `IDutControl`
returns each one, or `nullptr` where the backend has no such capability. The
alternative, one fat interface whose unsupported calls return "unsupported",
was rejected: it hides the asymmetry below instead of stating it. Adapters are
thin. The encoding stays in the opcode builders
(`src/stimulus/upper_tester_client.*`) and the Testability free functions
(`include/tc8/testability_client.h`, `src/testability_client/`).

## The asymmetry is the standard's, and a case reports it as a skip

Some things a TC8 case needs have no Testability service primitive: reading
the kernel's TCP state (RTO, retransmission count), reading urgent data,
conditioning the ARP cache, starting link-local autoconf, and injecting
faults. Those exist only on the opcode backend. A case declares the
capabilities it needs (`kRequiredCapabilities`, `dut_capabilities.h`). On a
backend without them the centralised gate skips the case as not applicable,
before any stimulus runs, instead of letting it time out as a FAIL. Many TCP
cases are therefore not portable to a Testability DUT. That is a limit of the
standard, stated honestly, not a defect of the seam. This tree does not invent
wire primitives the standard does not define (see docs/tech-debt.md TD-16).

Holding a socket in SYN-SENT is not one of these limits. The standard's CONNECT
only triggers the open, and service primitives may not wait, so both backends
return from `connectTcp` before the handshake ends. A returned socket is
therefore an issued open, not an established connection: a case that needs the
connection gets it from the tester's accept or from the wire. A failed open
arrives as a CONNECT Event on a Testability DUT, and `ITcpControl::connectEnd`
reads it.

Nor is a case that teaches the DUT a MAC for the tester and then grades that the
DUT used it. Nothing has to exist on the DUT before the teaching, so the standard
CREATE_AND_BIND, SEND_DATA and CLOSE_SOCKET run after it: sent raw, so the tester's
kernel resolves nothing, with each response heard at L2, because it goes to the
taught MAC (`IUdpControl::sendDatagramHeardAtL2`). A DUT that did not learn has to
ask before it can answer, and that ARP Request is what the case grades. A case
where the tester teaches only after the DUT has asked stays on the opcode backend:
there the reply is queued behind the resolution, so no socket id can come back.

The service-primitive call is carried the same way whenever the run has a wire. It is
the channel a registered extension implements DUT operations through, and one of them
pins a static ARP entry (`IArpStaticEntry`): from then on the DUT answers a MAC no
tester interface owns, starting with the install's own acknowledgement, which a
kernel-routed exchange would never hear. The other Testability controls stay
kernel-routed on purpose: the plain UDP send is the default its L2 form is told apart
from, and the TCP control's Events arrive on sockets of their own. A call that
completes a named step (`IServicePrimitiveControl::callAsStep`, names in
`tc8/stimulus_step_names.h`) also marks its E_OK Response, so a case waiting on the
step learns where in the capture it took effect, as it does from the opcode path's
awaited request.

## What an answer means, and who records it

A DUT-control call has three outcomes, and a `bool` cannot tell two of them
apart: the DUT did it, the DUT refused (and why), or no answer came. CLOSE and
ABORT return a `DutCallOutcome` with all three, the refusal reason in
backend-neutral terms (`kConnectionDoesNotExist` for PRS_TPSP E_TCP_CNE or
E_ISD, and for the opcode UT's unknown-socket status), because RFC 793 3.9
makes "CLOSE on a connection that does not exist is refused" a requirement a
case can grade. `createTcp` (testability CREATE_AND_BIND alone, gated by
`kCapTcpCreateClosed`) gives such a case a connection in CLOSED to ask about.
RECEIVE (normal and urgent) returns a `DutReceiveOutcome`: the bytes the DUT's
application got, a refusal, or no answer. A case grading delivery fails a wrong
answer or a refusal and stays inconclusive on no answer, because only an answer
says something about the DUT.

The UDP receive question has the same arm-then-trigger shape (`receiveUdp`). A
case gives it the probe and a sentinel, both as callbacks; the answer comes back
in-process and the stimulus records it in `Captured` (`udp_receive_answer.h`).
The opcode backend runs the probe and asks the DUT, whose `received=0` is an
affirmative answer. The testability backend binds the port, arms
RECEIVE_AND_FORWARD before the probe, and sends a well-formed sentinel datagram
after it. "Sentinel forwarded, probe not" is an observed discard; "neither
forwarded" is a silence, which is no answer and leaves the case inconclusive. The
premise is that a socket's receive queue keeps arrival order. The socket is bound
on any address so the sentinel, sent to the DUT's unicast address, proves the path
even when the probe went to an address the DUT is expected to refuse. A case's
machine reacts to the runner's stimulus-settled hook (`onStimulusSettled`), not to
a wire frame, so no control-channel frame is evidence for this family.

Every backend is handed out inside a `RecordingDutControl`
(`recording_dut_control.h`, applied by `makeDutControl`), which turns an action
the case needed and did not get into an unperformed stimulus, so a case that
ignores a result cannot grade the tester's failure as the DUT's silence
(docs/verdict_policy.md Section 2.1, hypothesis S). What counts depends on why
the call was made, which the case states with a `DutCallIntentScope`
(`dut_call_intent.h`): a stimulus by default (anything short of done is
recorded), a graded call (only no answer is recorded; a refusal is the DUT's
answer), or cleanup after the graded part (nothing is recorded). A receive is
a query: whatever the DUT answered is an observation, so only no answer is
recorded, outside cleanup. Accept and the state probe are observations and
record nothing.

## Seams a DUT's owner provides

A DUT can serve primitives this repository has no numbers for (PRS_TPSP reserves
groups without defining their primitives), and the harness must not hold numbers
that belong to the DUT's owner. The owner registers an extension from a translation
unit linked into the runner, the way extra cases are:

```cpp
TC8_REGISTER_DUT_CONTROL_EXTENSION(
    ::tc8::sce::DutControlBackend::kTestability,
    [](::tc8::sce::IServicePrimitiveControl &transport) {
        return std::make_unique<MyDutExtension>(transport);
    });
```

An extension derives from `DutControlExtension` (`dut_control_extension.h`), overrides
any of the optional seam accessors every backend shares (`IDutControlSeams`), and
reports the capability bits for exactly those seams. It is built over the backend's
service-primitive call, bound to the run's endpoint, timeout and source address, and
over nothing else, so it cannot drift from the control channel the run uses.

`makeDutControl` composes the registered extensions into the handle
(`dut_control_compose.h`). Each rule is a startup error, so a run ends before any
case sends rather than grading a DUT through code nobody named: an extension adds a
seam and never replaces the backend's; two extensions never offer one seam; an
extension's bits equal the seams it provides (a claim wider than the answer would run
cases into a nullptr, a narrower one would hide a seam). The handle returns an
extension's answer as given, so a wrong answer goes red in the case that declares the
bit. The run header names the extension behind each seam.

The seams an extension is likely to provide were split along their methods for this:
the TCP state query (`ITcpStateQuery`, `kCapTcpStateQuery`) answers an RFC 793 state
and is separate from the TCP_INFO counters (`ITcpInfoProbe`, `kCapTcpInfoProbe`); the
ARP plane is two seams, aging the cache (`IArpCacheAging`, `kCapArpCacheAging`) and
adding and removing a static entry (`IArpStaticEntry`, `kCapArpStaticEntry`), because a
DUT can pin a neighbour without any operation that ages its cache. Neither carries the
provocation, which is a UDP send. Until 2026-11-02 one seam and one bit held all three
operations, so a provider of the static half could not claim it without also claiming
aging it does not serve.

## How a case receives the seam

A case opts in with a stimulus overload that takes `IDutControl&`
(`test_case_traits.h` detects it). The CLI owns the backend and hands it to
`TestRunner::kickStimulus`. So the concrete backend headers are included only
by the CLI translation unit, not by the hundreds of case translation units.

## A decision recorded so it is not retaken

A listen-only case whose handshake completes leaves the Testability server an
accepted child socket and an accept Event that nobody collects, until
END_TEST. Silencing that with `LISTEN_AND_ACCEPT maxCon=0` as a "drain only"
mode was implemented and then rejected. PRS_TPSP defines `maxCon` as the number
of connections allowed to establish and gives 0 no meaning, so that would be a
tc8-dut-only convention a real ECU does not share, the opposite of this seam's
goal. The uncollected Event is the honest residue of the standard primitive,
and a real ECU behaves the same way. The opcode backend's passive open is a
single socket and has no child to leave.
