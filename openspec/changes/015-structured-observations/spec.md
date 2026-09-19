# Spec 015 – Structured Observations on the Result

## Specification ID
`015-structured-observations`

## Status
`Implemented`

## Summary

Expose the structured data the network-attribution and Certificate
Transparency checks already compute, so an embedding consumer can read
attribution, provenance and discovered hostnames as typed values rather than
by parsing rendered prose.

## Motivation

Both checks build rich structures and then flatten them to `[]string` before
the result leaves the library:

```go
// net
Records:  analyse.NetworkRecords(obs),   // []string
Findings: analyse.NetworkAttribution(...)

// ct
Records:  analyse.CTRecords(obs),        // []string
Findings: analyse.CertificateTransparency(...)
```

`finding.Result` carries `Findings`, `Checks`, `Errors` and `Targets`;
`CheckResult.Records` is `[]string`. So `netattr.Attribution`,
`netattr.SourceProvenance`, `analyse.NetworkHost` and `analyse.CTHost` are
computed, rendered, and discarded.

A consumer that needs the provider of a host, the jurisdiction it sits in, or
the hostnames Certificate Transparency disclosed has exactly one option today:
parse the record lines. That is a poor contract in a way worth being precise
about — it does not fail loudly. Reworded prose yields *no match*, which reads
as "no attribution" rather than as an error, and an unattributed host is
indistinguishable from one genuinely not in any cloud. The failure is silent,
and it is silent in the reassuring direction.

The records themselves cannot be made a stable contract instead. They are
prose intended for a reader, and `009` treats rendered output as presentation.
The prefixes introduced for `013` already concede the point: they exist so a
differ need not "pattern-match prose that may later be reworded".

This is the same argument `013` makes for snapshotting records rather than
findings — capture what was observed, not how it was described — applied one
level further down.

## Requirements

### R1 — Structured observations travel with the result

`finding.Result` SHALL carry the structured observations produced by checks
that compute them, alongside the existing rendered records.

- Rendered records SHALL remain, unchanged. This is additive; `013`'s record
  diffing and every existing consumer continue to work.
- A check that computes no structured observation SHALL contribute none. An
  absent observation SHALL be distinguishable from an empty one.

**Scenario: attribution is readable without parsing**
- **GIVEN** an assessment of a domain whose apex resolves into a known provider range
- **WHEN** the result is inspected programmatically
- **THEN** the provider, region, jurisdiction and matched prefix are available as typed values

**Scenario: a reworded record does not change the structured observation**
- **GIVEN** a change to the prose of a rendered record
- **WHEN** the structured observation is compared before and after
- **THEN** it is unchanged, because the two are produced independently

### R2 — Provenance travels with attribution

Every structured network attribution SHALL carry the provenance of the data
that produced it: the publishing source, the URL used, and when it was
fetched. The sources that failed to load and those served stale SHALL travel
with it.

Provenance is what lets a consumer tell *the host moved* from *our data
changed*. Without it, a consumer diffing two runs cannot distinguish the two,
and will report infrastructure change that did not happen.

**Scenario: a consumer can attribute drift to a data refresh**
- **GIVEN** two assessments of an unchanged domain, either side of a provider range file being refreshed
- **WHEN** the attributions are compared
- **THEN** the provenance differs and the attribution does not, so the consumer can suppress the difference

**Scenario: an unattributed address is not reported as clean**
- **GIVEN** an assessment during which a provider's ranges could not be loaded
- **WHEN** the result is inspected
- **THEN** the failed source is named, so an unattributed address is distinguishable from an address known to be in no provider range

### R3 — Timestamp granularity does not manufacture drift

Provenance timestamps SHALL be exposed at full precision, and the library
SHALL provide the means to compare two provenances for material equality
without regard to refresh time.

`provenanceLines` currently renders the date to the day for exactly this
reason: *"a timestamp that changes on every refresh would register as drift on
every run"*. Exposing a full `time.Time` without also exposing that judgement
would move a solved problem onto every consumer, and each would solve it
differently or not at all.

**Scenario: refresh time alone is not material**
- **GIVEN** two provenances differing only in fetch time
- **WHEN** they are compared for material equality
- **THEN** they compare equal

### R4 — Discovered hostnames are enumerable

Certificate Transparency enumeration SHALL expose the discovered hostnames,
each with its resolution state, as typed values.

The three-state resolution already modelled — resolves, NXDOMAIN, neither —
SHALL be preserved. `CTHost` documents that these are not negations of each
other: *"a query that failed leaves both false, and nothing may be concluded
from that."* A consumer feeding discovery must not be forced to collapse that
into a boolean.

**Scenario: discovered names are usable as discovery input**
- **GIVEN** an assessment of a domain with certificates issued for names that no longer resolve
- **WHEN** the result is inspected
- **THEN** each discovered name is available with its resolution state distinguishable between resolving, confirmed absent, and undetermined

## Non-goals

- **No new egress.** This exposes data already gathered by checks already
  subject to the egress profiles declared in `014`. No check gains a network
  dependency, and no profile changes.
- **No change to findings or their IDs.** `schema_version` and finding IDs are
  a public contract; this touches neither.
- **No removal of rendered records.** They remain the presentation surface.

## Notes on the serialised form

`Result` is serialised to JSON as a public artefact. Structured observations
SHALL be serialised alongside the rest, and SHALL be omitted entirely when
absent rather than emitted as empty objects — so that "not gathered" and
"gathered and empty" remain distinguishable in the JSON as they are in the Go
types.

`netip.Prefix` and `netip.Addr` marshal to their textual forms and round-trip,
so no custom marshalling is required.

## Consumer

Trawl's Change 006 Phase 8 (discovery and inventory enrichment) is blocked on
this. It needs provider, region, jurisdiction and provenance to enrich its
asset inventory, and Certificate Transparency hostnames as a discovery source
— and it holds an invariant that a check which never ran must never render as
a check that passed, which R2's failed-source reporting is what makes
possible.
