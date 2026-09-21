# Spec 016 - Service Reachability and Protocol Observations

## Specification ID
`016-service-reachability-and-protocol-observations`

## Status
`Proposed`

## Summary

Make Vantage the single structured observation owner for externally reachable
services and TLS protocol posture. The capability supersedes the supported
assessment roles of TCPScan and TLSAudit without initially reproducing their
raw-packet implementation. It provides a bounded, context-aware probe API over
standard-library transports. Raw-packet candidate discovery is deliberately
outside the foreseeable roadmap: its privilege, platform and deployment costs
are not justified by the anticipated use cases.

## Motivation

TCPScan's SYN scanner is genuinely useful for broad candidate-port discovery:
it can classify a SYN-ACK or RST without completing a TCP handshake. That is a
speed optimization for the question "which address/port pairs appear to have a
listener?" It is not proof that an intended application is usable.

TLSAudit necessarily performs protocol interaction for TLS evidence. Supported
protocols, ciphers, curves, certificates, SNI behaviour and STARTTLS cannot be
determined from a SYN response. Raw-packet discovery can reduce the candidate
set, but it cannot replace the handshake that produces the audit evidence.

Vantage is the right owner because it already owns structured observations,
coverage, egress profiles and injectable transports. Trawl needs evidence that
says what responded, at which layer, under which probe, with what uncertainty
and when. A boolean `open` result is too weak for the contact model and too
ambiguous for a measured-state risk ledger.

## Requirements

### R1 - Context-first, injectable probe API

Vantage SHALL expose service probes through the embedding API rather than
through package-global configuration or subprocess execution.

The probe API SHALL accept a context, an explicit target and a declared probe
profile. Dialers, clocks and protocol clients SHALL be injectable where that
makes scope enforcement or hermetic testing possible.

The default implementation SHALL use Go's standard library:

- `net.Dialer` for TCP connectivity;
- `crypto/tls` for TLS negotiation and certificate evidence;
- `net/http` for HTTP/HTTPS response evidence; and
- `context.Context` for cancellation and deadlines.

### R2 - Explicit probe layers

A request SHALL identify the layer being assessed:

- `tcp`: whether a TCP endpoint responds;
- `tls`: whether TLS negotiation produces a protocol result;
- `http`: whether an HTTP endpoint responds; and
- `starttls`: whether a declared mail protocol reaches its TLS transition.

A successful lower-layer result SHALL NOT be promoted implicitly to a
higher-layer result. A TCP response is not an HTTP response, and a TLS
negotiation failure is not a closed TCP port.

### R3 - Structured reachability observation

Results SHALL carry structured observations, alongside any rendered records.
Each service observation SHALL include:

```go
type ServiceObservation struct {
    Host           string
    Port           uint16
    Transport      string
    Protocol       string
    State          string // responding, not_responding, unknown
    Evidence       ServiceEvidence
    ObservedAt     time.Time
    ProbeProfile   string
}
```

`ServiceEvidence` MAY include the resolved address, response class, TLS
version, negotiated cipher, certificate summary, SNI name, HTTP status and
bounded server metadata. It SHALL NOT include credentials or unbounded response
bodies.

The result SHALL distinguish:

- `responding`: the requested layer produced a response;
- `not_responding`: the requested layer was reached sufficiently to conclude
  that it did not respond;
- `unknown`: policy, cancellation, timeout or an inconclusive transport error
  prevented a conclusion.

`unknown` SHALL NOT be converted into `not_responding`.

### R4 - Protocol evidence replaces TLSAudit assessment roles

The TLS probe SHALL support the protocol observations required by the library's
TLS audit capability, including supported protocol negotiation, certificate
summary, SNI and explicitly requested protocol checks. STARTTLS SHALL be a
separate declared protocol, not an accidental SMTP or IMAP connection.

Cipher-suite enumeration MAY be implemented through repeated controlled
handshakes, but the API SHALL disclose that it is an active protocol probe and
shall bound the number and duration of attempts.

Vantage SHALL not claim to reproduce TLSAudit's full result until contract and
golden-vector tests cover the corresponding evidence fields.

### R5 - Declared targets and bounded breadth

The first supported profile SHALL probe explicitly declared host/port/protocol
endpoints and a bounded set of ports supplied by the caller. It SHALL NOT scan
arbitrary CIDR ranges or an unbounded common-port list by default.

A future candidate-discovery profile MAY support common-port or CIDR scanning,
but only when its scope, rate, packet budget, timeout and evidence semantics are
explicit. It SHALL be behind a separate profile from declared-service probing.

### R6 - Egress profiles and scope enforcement

Every probe profile SHALL declare its egress class and target contact. The
probe SHALL use the injected target transport, so an out-of-scope host is
unreachable at the network boundary rather than merely omitted by the caller.

A probe request SHALL be attributable to a named check, target, protocol layer,
reason and observation timestamp. It SHALL never follow an out-of-scope
redirect, certificate name or discovered host implicitly.

### R7 - Non-destructive operation

Probes SHALL not exploit, brute-force, authenticate, upload data, claim
resources, enumerate credentials or intentionally degrade availability.

HTTP probes SHALL use bounded, read-only requests. TLS and STARTTLS probes
shall stop after the protocol evidence needed by the requested profile is
collected. A probe that exceeds its deadline SHALL return `unknown` or a
layer-specific failure, not a reassuring success.

### R8 - Concurrency, rate and resource bounds

Probe profiles SHALL define maximum concurrency, per-target timeout, total
request budget and cancellation behaviour. Concurrent probing SHALL not bypass
scope or rate controls.

The implementation SHALL report enough timing and error evidence to benchmark
standard TCP connect probing against any future raw-SYN backend.

### R9 - Raw-SYN backend is out of scope

Vantage SHALL not add raw-packet, libpcap, cgo or elevated-privilege
requirements for the foreseeable roadmap. Declared-service TCP connect probing
is the supported candidate-discovery mechanism.

Raw-SYN work MAY be reconsidered only through a new proposal if the anticipated
use cases change materially. Such a proposal would need to justify the
privilege, platform and deployment burden before implementation is considered.

### R10 - Compatibility and retirement contract

The Vantage CLI MAY retain compatibility adapters while consumers migrate, but
new consumers SHALL use the structured embedding API. TCPScan and TLSAudit
functionality SHALL not be copied as independent engines inside Vantage.

Once contract tests cover the required protocol evidence and Trawl consumes the
new observations, the two tools MAY be retired from the supported toolchain.

Retirement SHALL be treated as a staged migration, not as deletion on the day
the first replacement probe lands. Before either repository is removed from
the supported toolchain, the following evidence SHALL exist:

1. Vantage contract and golden-vector tests cover every supported TCPScan and
  TLSAudit workflow that remains advertised, or the workflow is explicitly
  marked unsupported with a migration note.
2. Trawl and every other supported consumer use Vantage's embedding API and no
  supported build invokes either legacy tool or imports its package.
3. Vantage documents the replacement commands and API examples, including the
  differences between declared-service probing and broad candidate discovery.
4. A deprecation release of each legacy repository points users to Vantage,
  states the last supported version, and identifies any intentionally dropped
  raw-SYN or report-generation behavior.
5. At least one release cycle passes with no unresolved migration defect or
  consumer relying on the legacy output format.

Only after these gates pass SHOULD TCPScan and TLSAudit be removed from the
supported implementation set. GitHub archival is optional housekeeping, not a
technical prerequisite: a repository MAY remain public and read-only as a
portfolio and historical project. Its README and repository metadata SHALL
identify it as deprecated, link to Vantage as the supported successor, state
the last supported version, and preserve its history and licenses. An archive
notice, if used, SHALL direct users to Vantage rather than claiming that every
historical implementation detail has been reproduced.

## Non-goals

- No vulnerability exploitation or credential testing.
- No unrestricted Internet-wide scanning profile.
- No attacker-contact inference. A service response is exposure evidence, not
  evidence that an attacker contacted the service.
- No probability, severity or risk scoring in Vantage. Vantage reports facts;
  Trawl and its risk model consume them.
- No raw-packet or privileged scanning profile.

## Testing

- Local TCP listener tests for responding, refused and timeout states.
- TLS test-server tests for SNI, certificate summary, protocol negotiation and
  handshake failure.
- HTTP test-server tests for bounded read-only response evidence and redirect
  refusal.
- STARTTLS tests for the declared protocol transition.
- Scope-guard tests proving zero packets reach an out-of-scope target.
- Cancellation, timeout, concurrency and rate-budget tests.
- Serialization tests distinguishing absent, empty and unknown observations.
- Contract tests proving the same observation shape is consumed by Trawl.
- Contract tests proving declared TCP connect probing remains the supported
  candidate-discovery path.
