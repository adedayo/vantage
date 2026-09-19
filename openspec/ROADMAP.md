# Roadmap

Specs `002`–`008` are implemented. Specs `009`–`015` are proposed and are
sequenced below, because the dependencies between them are strict.

## Dependency graph

```
009 findings & reporting  ──┬──> 010 aggregate audit ──┬──> 013 baseline & drift
                            │                          │
                            ├──> 011 deep analysis      └──> 014 agentic readiness
                            │
                            └──> 012 attack surface ──> 015 structured observations
```

`009` is foundational: it replaces string output with a findings model, so every
later spec depends on it. `014` depends on `010` because the capability manifest
and MCP tools are generated from the check registry. `015` depends on `012`
because it exposes the observations the attack-surface checks compute.

## Phases

### Phase 1 — Foundation (`009`, `010`)
Refactor the 15 existing checks to return findings, add the renderers, add the
`audit` command and the check registry. No new detection capability, but this is
what makes everything after it possible — and it delivers immediate value
through `audit`, JSON output and `--fail-on`.

**Risk**: touches all 15 commands. Mitigated by keeping `--format text` output
byte-identical for the existing single-record commands, verified by golden files.

### Phase 2 — Depth (`011`)
Make the existing checks genuinely useful: SPF recursion and the ten-lookup
limit, DMARC organisational-domain fallback and external-destination
verification, DNSSEC chain validation, MTA-STS policy fetch, plus TLS-RPT, BIMI
and MX hygiene.

Highest security value per unit of effort, because the DNS plumbing already
exists.

**Complete.** All 57 rules specified by `011` are catalogued and emitted, each
citing its controlling RFC section. The account below is chronological, since
the order the work landed in explains several of the decisions.

DKIM key analysis (`SURF-DKIM-001`–`006`) and TLS-RPT
(`SURF-TLSRPT-001`–`002`) have landed, the latter as a new check and command.
Recursive SPF evaluation has also landed (`SURF-SPF-006`, `007`, `009`, `010`):
includes and redirects are now followed through the resolver cache to count
DNS-querying mechanisms against the RFC 7208 ten-lookup limit, count void
lookups, detect include cycles and flag unusable include targets.

Two constraints in shared code were fixed while building this, both covered by
tests. `pkg/dns.go` advertised no EDNS0 buffer, so responses carrying large SPF
trees failed to unpack and were reported as an unreachable resolver — disabling
the check on the domains it matters most for. And `pkg/audit/cache.go` treated
each 255-byte string of a long TXT record as a separate record, which fragmented
2048-bit DKIM keys into false `SURF-DKIM-006` "malformed" findings and would
have made one long SPF record look like a duplicate.

Still outstanding at that point: DNSSEC chain validation.

MX hygiene (`SURF-MX-001`–`004`), CAA tree-climbing (`SURF-CAA-001`–`005`),
BIMI (`SURF-BIMI-001`–`003`) and the two remaining DMARC rules — organisational-
domain fallback (`SURF-DMARC-009`) and external-destination verification
(`SURF-DMARC-006`) — have now landed, taking the catalogue to 40 rules. BIMI is
a new check and command; CAA now climbs the domain tree and stops below the
public suffix, so a policy inherited from a parent is reported as inherited
rather than absent.

NXDOMAIN is reported by `pkg/dns.go` as absence rather than as a generic error,
so callers can distinguish "no such name" from "check failed". DMARC
organisational-domain fallback depends on this, since a subdomain with no policy
of its own usually does not exist. SERVFAIL remains an error: the resolver
genuinely could not answer.

`SURF-MX-005` (all exchangers within one ASN) is deferred to Phase 3, where
spec `012` introduces the network attribution it needs. Implementing it now
would mean inventing a proxy for an ASN and labelling it as one.

MTA-STS (`SURF-MTASTS-001`–`008`) has now landed, taking the catalogue to 48
rules and leaving DNSSEC chain validation as the last outstanding work in this
phase. This is the first check to leave DNS: the policy file is fetched from
`https://mta-sts.<domain>/.well-known/mta-sts.txt`, with redirects refused and
the certificate validated per RFC 8461 §3.2. Verifying only the TXT record
would attest to an intention rather than a control, since a domain can
advertise a policy it does not serve.

`--no-network` distinguishes checks that *use* egress from those that *cannot
run without* it. A check that still detects a missing control from DNS alone
survives `--no-network` and skips only its policy-dependent rules; excluding
every check declaring HTTPS egress would report a domain publishing no MTA-STS
policy as clean in exactly the mode a cautious operator would choose.

The standalone `mtasts` command records retrieved evidence alongside the DNS
answers, and that evidence is absent under `--no-network`, so a report never
implies a document was inspected when it was not.

DNSSEC chain validation (`SURF-DNSSEC-001`–`008`) has now landed, completing
Phase 2 and taking the catalogue to 56 rules. The `dnssec` check no longer
reports DNSKEY presence, which conflated a signed zone with a validated one:
it now retrieves the parent's DS record, matches it against the published keys
by tag, algorithm and recomputed digest, assesses algorithm strength and RSA
key size, reports signature expiry, and identifies the denial-of-existence
strategy. The two conditions that matter most are invisible to presence
checking and opposite in character — an island of trust (`002`), where signing
costs effort but protects nobody, and a broken chain (`003`), which is an
outage rather than a weakness because validating resolvers return SERVFAIL for
every name in the zone.

This required DNSSEC-aware querying: `pkg/dns.go` gained DO-bit variants, since
without it resolvers strip RRSIG records and the AD bit is meaningless. Every
finding now carries the resolver's AD bit as evidence, which is what separates
"this zone is signed" from "the resolver in front of the user validates it".

Two false-positive sources were closed while building it. Providers that
synthesise minimal NSEC records per query ("black lies", used by Cloudflare
among others) are recognised, because their chains cannot be walked and
reporting them as enumerable would train readers to ignore `007` where it does
matter. And a DS whose digest was never recomputed is not reported as broken:
"we did not check" is not evidence of a fault.

### Phase 3 — Surface (`012`)
Subdomain takeover, zone transfer, delegation hygiene, wildcard detection,
CT enumeration, network attribution. Introduces an embedded fingerprint database
and optional third-party egress, so it needs the profile machinery from `010`.

**Complete.** Wildcard detection (`SURF-WILD-001`–`003`), nameserver and
delegation hygiene (`SURF-NS-001`–`008`), subdomain takeover
(`SURF-TKO-001`–`005`), zone transfer (`SURF-AXFR-001`, `002`), network
attribution (`SURF-NET-001`–`003`) and CT enumeration (`SURF-CT-001`–`003`),
taking the catalogue to 81 rules. `SURF-NS-009` and `SURF-AXFR-003` are not
implemented; the reasons are recorded below.

**Ordering.** Wildcard detection comes first because `012` requires it to run
before takeover. In a zone with a wildcard every name resolves, so a dangling
CNAME's target answers too and the NXDOMAIN reasoning behind `SURF-TKO-001` and
`004` is unavailable. Takeover then precedes the rest as the highest-impact
check in the spec.

**Naming.** The wildcard check registers as `wild`, not `wildcard`: the
catalogue invariant requires a rule's ID segment to match its check name, the
spec fixes the IDs as `SURF-WILD-*`, and the IDs are the public contract.

#### Wildcard detection
A wildcard is asserted only when at least two high-entropy labels return the
*same* answer. One label resolving proves that name exists, not that the zone
answers for everything, and a wildcard asserted from a single probe would
suppress genuine takeover findings. A probe whose query failed contributes
nothing rather than an empty answer, since the evaluator reads an empty answer
as "this name does not resolve".

The authorisation statement required by `012` landed in the README with this
check, as specified, rather than being deferred to the first AXFR attempt.

#### Delegation hygiene
The first check to interrogate the target's authoritative servers individually
rather than accept whatever a resolver returns — the only way to observe a lame
server, a delegation that disagrees with the zone, missing glue, or an
authoritative server that also recurses for strangers.

Serials are compared only within a provider, grouped by the registrable domain
of the nameserver's own name. `github.com` is served by Route 53 and NS1, whose
serial schemes are unrelated (Route 53 pins the serial at 1), so a cross-provider
comparison reports the most resilient arrangement a domain can have as a
replication fault.

An unreachable parent yields no parent-derived findings at all, rather than an
empty NS set that would read as total disagreement under a rate-limiting TLD
server. A nameserver that did not respond is reported as lame — unreachable from
here is unreachable for some users too — but at reduced confidence, since
silence from one vantage point is weaker evidence than a reply omitting the AA
bit.

`SURF-NS-009` (expired nameserver domain) needs registration data, which is not
DNS and needs its own source and egress decision. It is not implemented.

#### Subdomain takeover
`pkg/takeover` holds the embedded fingerprint database: twenty services, each
carrying a schema version, provenance and a citation establishing that an
unclaimed name really can be claimed. `Validate` rejects any entry detectable by
neither NXDOMAIN nor an HTTP body, since such a fingerprint could only produce a
guess dressed as a Critical finding.

Hosts are supplied (`--hosts`, `--hosts-file`) and the apex is always assessed;
they are never guessed, because inventing subdomains to probe is the
brute-force enumeration `012` forbids. Certificate Transparency, described
below, is the sanctioned way to widen the set.

An alias pointing back inside the audited domain is never a takeover, because
the target is already the organisation's. Without that guard, "www to the apex"
is reported as third-party exposure whenever an organisation's own domain
matches a fingerprint suffix. Unverified `SURF-TKO-003` reports are raised only
for services where an abandoned name can be claimed by anybody, not for
edge-case services whose conditions this tool cannot observe: a CDN alias such
as `bbc.co.uk`'s Fastly record would otherwise fire on most CDN-fronted domains
and teach readers to skip the rule.

`SURF-TKO-002` (HTTP corroboration) retrieves the body served by an aliased
host and matches it against the fingerprint. It is assessed before the NXDOMAIN
rules, because a service's own "this name is unclaimed" page is stronger
evidence than a missing DNS record. HTTPS is tried first and HTTP second, since
an unclaimed name usually has no valid certificate and refusing to fall back
would leave the strongest signal unread. Redirects are refused and the body is
bounded at 64KB.

A failed retrieval sets `Fetched` false rather than an empty body, so the
absence of a match is never read as "this name is in use" — the same shape as
the six defects described under *Testing convention* below. Suppression of the
unverified `SURF-TKO-003` is keyed on whether corroboration actually succeeded
for that host, not on whether corroboration was enabled for the run.

#### Network attribution
`pkg/netattr` carries the IANA special-purpose address registries for IPv4 and
IPv6, and loads published provider ranges from AWS, Google Cloud, Cloudflare and
Fastly. Ranges are cached for seven days; when a source is unreachable a stale
entry is used and its age is disclosed in the report, an old answer being more
use than none.

Loopback and unspecified addresses are excluded from `SURF-NET-001`. Publishing
`127.0.0.1` for a name is a null-routing practice, not a disclosure of internal
addressing, and reporting it would fire on a deliberate configuration.

Azure is absent. Microsoft publishes the same data as a Service Tags file —
3,321 tags and roughly 108,000 prefixes with region metadata, ample for
attribution — but only at a URL carrying both a GUID and a publication date,
and only the two most recent weekly files are retained; every older date
returns 404. Consuming it means guessing recent Mondays until one answers,
against a GUID Microsoft can rotate without notice. The failure mode is silent:
Azure hosts would quietly become unattributed and nobody would learn that
attribution had stopped. Reporting them as unattributed today is the same
outcome without the false confidence, so adding Azure needs a staleness signal
that says out loud when the file could not be found. Jurisdiction is inferred
from provider region naming and is an approximation of where data sits, not a
legal determination; `normaliseRegion` strips a GCP zone letter but not an AWS
trailing digit, the two schemes being different.

`SURF-NET-001` and `SURF-NET-003` are assessed once per host per provider, not
once per address. A host answering with four addresses in one region is one
fact about that host; the first live run against `bbc.co.uk` with enumeration
produced 262 findings for 73 hosts, which is the volume at which a reader stops
reading. The addresses, prefixes and regions are all retained as evidence, so
grouping costs nothing that could be used to verify the claim. Special-purpose
addresses are still reported individually, each being a distinct disclosure.

**Partial coverage is disclosed.** `Load` returns an error only when *every*
provider publication fails; if one fails and the rest succeed the run continues,
and that is the check's most dangerous failure mode. Coverage gaps cause false
negatives, not false positives: with the AWS ranges missing, every AWS address
reads as unattributed, `SURF-NET-001` stops firing, and the report is
indistinguishable from a domain using no third-party hosting. Reproduced against
`amazon.com` with the AWS file withheld — twelve plainly-AWS addresses rendered
`(unattributed)`, state `ok`, grade A, and nothing anywhere said why.

The failed sources are now carried into the observation and named in the check
records, and affected addresses read `not attributed — coverage incomplete`
rather than `unattributed`, since the latter asserts the address belongs to no
known provider, which is exactly what could not be established. Because text is
the default format, the renderer promotes any record prefixed `warning:` to a
`Warning:` line, so a degradation is not visible only to readers of JSON.

Stale data is disclosed on the same principle but kept distinct from failure.
When an endpoint is unreachable and a cache entry older than the seven-day
lifetime exists, the entry is used — a prefix that moved last week is almost
always still announced by the same operator, and discarding it would remove
attributions that were correct yesterday — and the record names the source and
the date it was cached. Coverage is complete in that case; only the refresh
failed, and conflating the two would overstate the problem.

`pkg/netattr` coverage went from 44% to 90% with these, `cache.go` having had
none at all. It holds the lifetime, the atomic write and the stale fallback,
which is the whole of what stands between the check and the network.

**Sources carry fallbacks.** Each operator's ranges are described by an ordered
list of endpoints, tried until one both fetches and parses; a parse failure
disqualifies an endpoint exactly as unreachability does, since an operator that
changed format is as unusable as one that is down. When all of them fail, every
failure is named, because a caller told only about the last would investigate
the wrong endpoint.

Only Cloudflare publishes a genuine second endpoint, its JSON API, and the two
address families are extracted separately so each plain-text list falls back to
the equivalent half rather than double-counting. Google's `goog.json` is
deliberately *not* a fallback for `cloud.json`: it lists every Google netblock
including `8.8.8.0/24`, carries no region, and would attribute Google's own
infrastructure to a customer cloud — an attribution indistinguishable from a
correct one while being wrong, which is worse than reporting the source as
unavailable. AWS and Fastly publish one endpoint each, so for those three the
stale cache is the resilience and its use is disclosed.

**Attribution carries provenance.** Spec `013` diffs records between runs and
requires that false drift be avoidable, since it destroys trust in the signal
faster than missing drift does. Attribution is derived from data this tool
fetches, so it can change without the audited domain changing at all. Each
provider's ranges therefore record the endpoint actually used — which may be a
fallback — and the date obtained, emitted as a `provenance:` record. The date is
rendered to the day rather than the second, because a timestamp changing on
every refresh would itself register as drift on every run.

`finding.IsDiagnosticRecord` and `CheckResult.ObservedRecords` mark the
distinction in shared code: records prefixed `warning:` or `provenance:`
describe the run, everything else describes the domain. A differ can then
exclude run state without pattern-matching prose that may later be reworded.

This unblocked `SURF-NS-002` and `SURF-MX-005`. Both are reported at low
confidence when every host sits under the audited domain itself: `google.com`'s
`ns1`–`ns4.google.com` are vanity names that reveal nothing about the underlying
provider, and a concentration finding derived from them would be an inference
from a naming convention. MX provider derivation moved to retrieval so it can
use the public suffix list — a two-label heuristic would treat unrelated
`.co.uk` organisations as one provider.

#### Certificate transparency
`ct` is the sanctioned way to widen the host set that takeover and attribution
assess, and enumeration runs before the checks so a discovered name is assessed
like one supplied by hand. It is opt-in behind `--enumerate` because it queries
a third party and yields an inventory rather than a verdict. Failure is
non-fatal: the run continues with the names given.

Names outside the audited domain are discarded. A certificate is frequently
shared across unrelated domains, and reporting those names would attribute other
organisations' infrastructure to the target.

Cert Spotter and crt.sh are both queried, in that order, until one answers. The
`Source` interface was written before a second source existed; on 3 August 2026
crt.sh returned 502 for every query, including for unrelated domains, and adding
Cert Spotter behind the existing interface required no change to the check above
it. A check that reports "could not enumerate" whenever one free service has a
bad afternoon is a check people turn off. When no source answers, every failure
is named, since a caller told only about the last one would investigate the
wrong service.

`SURF-CT-002` matches whole labels against a deliberately short keyword list and
skips the registrable domain, and is reported at medium confidence. Substring
matching would fire "dev" on `developer.example.com`, and an organisation called
Test Ltd is not leaking an internal hostname by owning `test.com`. A keyword
heuristic suggests; it does not establish.

Both per-name CT rules report once per group rather than once per name. The
first run against `bbc.co.uk` produced 83 findings, 60 of them `SURF-CT-002`,
and every one was a true positive — the keyword list was doing its job. The
defect was that 60 rows carried three facts: the zone uses `.test.`, `.stage.`
and `admin.` conventions. Once a reader knows the convention, the forty-third
hostname changes no decision. Grouping by keyword takes the same audit to 6
findings with all 60 names kept as evidence. Precision and volume are separate
problems, and a report nobody finishes is not made better by being correct.

That triage exposed a second defect one level up. Grading counted a
medium-confidence keyword guess exactly as heavily as an unsigned delegation
the resolver had proved, so `SURF-CT-002` alone could saturate the `Medium >= 3`
threshold and set the grade before any other check spoke. The catalogue records
a confidence for every rule and the grade was the one place it mattered most,
which is where it was being discarded. Grade version 2 demotes a finding one
severity band for medium confidence and two for low before applying the
thresholds. Only 10 of the 81 rules are below high confidence, so the change is
narrow by construction, and all 5 critical rules are high confidence — nothing
that should fail a domain was softened. Demotion rather than exclusion, because
a serious finding held with less certainty still counts for something: a
low-confidence critical lands at medium and stays visible. Reported severities
are untouched, so the counts still describe what was found; only the grade is
adjusted. `bbc.co.uk` moves from C to B, which is the right answer — its one
real issue is DNSSEC, not the naming of its test estate.

#### Zone transfer
Every authoritative server is tried, not merely the first: a zone is only as
protected as its least well configured server, and the common failure is one
forgotten secondary. Transferred data is counted and discarded as it streams,
with a five-record sample retained — enough to prove the disclosure without
republishing the estate the finding says should not have been available.
`--save-zone` is not implemented, satisfying the spec's requirement that nothing
be written to disk by default.

Two deliberate deviations from `012`. `SURF-AXFR-003` (IXFR permitted) is not
implemented: a server permitting IXFR but not AXFR is rare and the rule would
mostly restate `001`. And the check is in `surface` and `deep` only, not
`standard`, because `standard` is what a bare `vantage audit example.com` runs
— an AXFR attempt against every nameserver of a domain the user has not yet
thought about conflicts with the same spec's requirement that the tool not
resemble an attack, and some intrusion detection systems alert on it.

The check reports `check_failed` unless at least one server gave a definitive
answer; `analyse.ZoneTransferAssessed` makes the distinction explicit and
testable. Without it, a zone whose servers gave no answer reports `ok` with no
findings and grade A — "we could not test this" rendered as "this passed", on
the check where a false reassurance is most costly.

Refusal is recognised in several forms, because real servers vary: `google.com`
declines by returning a response with no SOA rather than an rcode, and
`bbc.co.uk` answers AXFR with FORMERR (`dig` confirms this is their rejection
style rather than a malformed request from this tool). Recognising only REFUSED
would report most correctly configured nameservers as untested. SERVFAIL is
excluded, because a transient internal failure is not a policy decision and a
retry might yet hand over the zone.

**Verification limits.** The successful-transfer path is verified against a mock
nameserver serving a real zone over TCP, not against a live open server. No
publicly-authorised open server could be reached: `zonetransfer.me`'s
nameservers accept TCP/53 connections and answer an ordinary SOA query over TCP,
but do not respond to AXFR, and `dig` times out identically. The negative paths
— refusal in four forms, unreachable, and answered-without-a-zone — are verified
against both mocks and live infrastructure.

#### Testing convention
Six defects in this project's history have shared one shape: a definitive answer
read as a failure, or a failure read as a definitive answer. All of them live at
the boundary between retrieval and judgement, which is precisely the seam that
`pkg/analyse`'s pure-function tests exclude by construction. The most recent was
in takeover: `pkg/dns.go` reports NXDOMAIN as `ErrNotFound` with a nil message
and the existence probe discarded errors, so the one answer the check depends on
never reached the rules — every unit test passed, because the judgement was
correct and only the retrieval was blind.

New checks therefore carry at least one end-to-end test against a mock resolver
for the condition they exist to detect, plus its converse, that a failed query
yields nothing. Both exist for takeover in `pkg/audit/takeover_check_test.go`
and for zone transfer in `pkg/audit/zonetransfer_check_test.go`, the latter
asserting all three outcomes through the whole path — NS discovery, address
resolution, transfer, judgement, finding — and asserting that the disclosure
finding carries the record count, the serial and a sampled hostname as evidence
rather than merely a verdict. The transfer port is a package variable so the
zone can be served unprivileged; a test that needs root is a test that does not
run. Retrofitting this shape to the checks that predate the convention is
outstanding.

A related fix in shared code: the runner retains a failing check's records, so
the evidence of which servers were tried survives the failure path and a blocked
network can be told from a broken tool.

**Not implemented in Phase 3:** `SURF-NS-009` (needs registration data),
`SURF-AXFR-003` (would mostly restate `SURF-AXFR-001`) and `SURF-TKO-006`
(unallocated cloud space, which needs range data at a granularity the published
provider files do not offer). Retrofitting the end-to-end testing convention to
the checks that predate it remains outstanding.

### Phase 4 — Continuity (`013`)
Baselines, drift classification and suppression. Depends on the deterministic
ordering guaranteed by `009`.

### Phase 5 — Agents (`014`)
Capability manifest, JSON Schemas, finding catalogue commands, token-economy
flags and the MCP server. Deliberately last, because a manifest generated from
an incomplete registry would need rewriting at every earlier phase.

Note that several `014` requirements — stable exit codes, structured errors,
stdout/stderr discipline, evidence and confidence on every finding — are
**obligations on the earlier phases**, not deferred work. They are specified in
`009` and must be honoured as the foundation is built, otherwise Phase 5 becomes
a retrofit.

### Phase 6 — Embedding (`015`)
Structured observations on the result: network attribution with its provenance,
and Certificate Transparency hostnames, exposed as typed values rather than as
rendered prose.

Additive and small, but it is the phase that makes the library genuinely
embeddable. Everything needed already exists — `netattr.Attribution`,
`SourceProvenance`, `analyse.NetworkHost`, `analyse.CTHost` — and is discarded
at the boundary, so today a consumer's only route to it is parsing record
lines. That parse fails silently and in the reassuring direction: reworded
prose yields no match, which reads as "no attribution" rather than as an error.

Driven by a real consumer. Trawl's vantage integration is blocked on it.

## Cross-cutting concerns

- **`cmd/` is at 0% test coverage.** Address during Phase 1, before the command
  surface grows further. *(Now at ~37%; `pkg/scanner` at ~41% is the weak spot.)*
- **Safety**: specs `012` and `014` add checks that query third-party
  infrastructure. The authorisation statement required by `012` should land in
  the README with the first such check, not afterwards.
- **Schema stability**: once `009` output ships, `schema_version` and finding IDs
  become a public contract. Treat them with the same care as the library API.
