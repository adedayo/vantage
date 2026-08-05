# Embedding vantage

vantage is a library first and a command second. The `vantage` binary is an
ordinary consumer of the same interface described here — it holds no private
hooks — so anything the CLI can do, an embedding tool can do.

This document is the contract. Everything in `pkg/audit` not described here
should be treated as internal.

## The interface

```go
type Assessor interface {
	Catalogue(ctx context.Context) (Capabilities, error)
	Assess(ctx context.Context, req Request) (*finding.Result, error)
}
```

Two methods: ask what the library can do, and ask it to do some of that.

```go
import (
	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/audit"
)

resolver := vantage.NewClient(vantage.ConfigFromEnv())

assessor, err := audit.NewAssessor(resolver,
	audit.WithVersion("myapp/1.4.0"),
	audit.WithConcurrency(4, 8),
)
if err != nil {
	return err
}

result, err := assessor.Assess(ctx, audit.Request{
	Targets:   []string{"example.com"},
	Selection: audit.Selection{Profile: audit.ProfileStandard},
})
```

`Assessor` is narrow on purpose. Resolvers, timeouts and concurrency are
constructor-time configuration, not part of the calling surface — and two
methods are trivial to fake, which is what stops a consumer's tests reaching the
network.

### Constructor options

| Option | Purpose |
| --- | --- |
| `WithVersion(v)` | Stamps results with **your** build's version, for provenance |
| `WithHTTPClient(d)` | HTTP egress for checks that fetch a policy file or page body |
| `WithConcurrency(targets, checks)` | Default parallelism; a `Request` may override |
| `WithRangeStore(s)` | Shares downloaded provider ranges across assessments |

`WithVersion` takes the embedding build's version, not vantage's. A result
stamped with the library version misattributes findings after your own release,
and a consumer comparing two stored results would see no reason for a change
that your code caused.

## Egress is injected, never ambient

The resolver is a required argument to `NewAssessor`, not an option. There is no
package-level default and no fallback: `NewAssessor(nil)` is an error, and a
runner without a resolver refuses to query rather than reaching for an ambient
client.

This is the load-bearing property. An assessor that could invent its own egress
would defeat any scope guard wrapped around it, silently, at the moment it
mattered most.

The same applies to HTTP. If you are enforcing scope, wrap **both** boundaries:

```go
assessor, err := audit.NewAssessor(guardedResolver,
	audit.WithHTTPClient(guardedHTTPClient))
```

Guarding DNS alone still discloses your target list to third parties through the
MTA-STS and subdomain-takeover paths.

`vantage.Doer` is a one-method interface (`Do(*http.Request) (*http.Response, error)`),
so `*http.Client` satisfies it and so does a guard of your own. Use
`vantage.NewHTTPClient` if you want the library's defaults — TLS 1.2 floor, no
redirects, keep-alives disabled.

**No configurable state lives at package level.** Two assessors built under
different authorisations can run concurrently in one process without either
observing the other's targets.

## A nil error does not mean everything succeeded

`Assess` returns a non-nil error only when the run itself could not proceed. A
check that fails is recorded against that check and the rest continue — one
unreachable nameserver must not deny you the other twenty answers.

So a nil error means *the run completed*, not that everything worked. Inspect
`result.Checks` and `result.Errors`.

### Four states, and why they do not reduce to two

Every check settles on exactly one of:

| State | Meaning |
| --- | --- |
| `finding.StateOK` | Ran; the property was present |
| `finding.StateNotFound` | Ran; the property was definitively absent |
| `finding.StateNotChecked` | Did not run — filtered by profile, policy or `NoNetwork` |
| `finding.StateCheckFailed` | Ran but could not reach a conclusion |

The distinction between `not_found` and `check_failed` is the one that matters.
The first is a measurement; the second is the *absence* of one. A consumer that
maps these onto a boolean will report an unmeasured control as a passing
control, which is the single most damaging thing a security tool can do — it
converts an unknown into a reassurance.

If you must map to your own vocabulary, map unknown states to your most
pessimistic value, not your most optimistic one.

### Errors carry codes, not just messages

`result.Errors` holds `finding.CheckError` values with a stable `Code`
(`ErrCodeTimeout`, `ErrCodeResolverUnreachable`, `ErrCodeNotFound`,
`ErrCodeInvalidRecord`, `ErrCodeOutOfScope`, `ErrCodeNetworkDisabled`,
`ErrCodeInternal`) and a `Retryable` hint. Switch on the code; never parse the
message.

Classification tests wrapped sentinels first and message substrings only as a
fallback, so rewording a message cannot change a verdict. The sentinels are
exported from `pkg`:

```go
errors.Is(err, vantage.ErrNotFound)
errors.Is(err, vantage.ErrResolverUnreachable)
errors.Is(err, vantage.ErrNetworkDisabled)
errors.Is(err, vantage.ErrOutOfScope)
errors.Is(err, vantage.ErrInvalidRecord)
```

`ErrOutOfScope` is declared but never returned by vantage itself. It exists so
that a consumer's scope guard and vantage's classifier share one concept, rather
than meeting through a substring match on an error message.

## Shaping a request

```go
type Request struct {
	Targets             []string
	Selection           Selection
	Hosts               []string
	Enumerate           bool
	ExpectJurisdictions []string
	Concurrency         int
	CheckConcurrency    int
	Observer            func(Progress)
}
```

Everything that shapes an assessment lives in the request, so two concurrent
requests under different scopes cannot interfere.

`Selection` chooses checks: a `Profile` (`quick`, `standard`, `email`,
`surface`, `deep`), then `Only` to replace its membership, then `Skip`, which is
applied last and always wins. `NoNetwork` excludes anything needing egress
beyond DNS. An unknown name in `Only` or `Skip` is an error rather than a silent
no-op — a caller who misspells a check name would otherwise believe they had
assessed something they had not.

`Hosts` are additional names to examine for subdomain takeover. **Nothing is
ever guessed to fill this.** Inferring subdomains would be brute-force
enumeration, and would report on hosts the domain never published.

`Enumerate` discovers further hosts from Certificate Transparency. It is opt-in
because it queries a third party.

`ExpectJurisdictions` takes ISO 3166-1 alpha-2 codes. Empty means no expectation
was stated, and the jurisdiction rule is then **not evaluated** rather than
evaluated against a default. A default here would invent an operator policy
nobody declared.

## Progress

Set `Request.Observer` to receive structured events. It is called from multiple
goroutines and must be safe for concurrent use.

```go
type Progress struct {
	Phase                     Phase   // target-started, check-completed, target-completed
	Target                    string
	Check                     string        // check-completed only
	State                     finding.State // check-completed only
	TargetsDone, TargetsTotal int
	ChecksDone, ChecksTotal   int
}
```

Switch on `Phase` and ignore phases you do not handle, so new phases are
additive.

`State` travels with the event so a consumer can show live coverage without
waiting for the run to end. Collapsing progress into a percentage throws away
the only part a person watching actually needs: the difference between "this
check finished and found nothing" and "this check finished and could not run".

`ChecksDone`/`ChecksTotal` are meaningful only within the current target, since
targets run concurrently.

## Building against the catalogue, not a hard-coded list

```go
caps, err := assessor.Catalogue(ctx)
```

`Catalogue` makes no network queries. That is deliberate: an operator deciding
whether to authorise a run at all should not have to permit egress in order to
read what the run would do.

```go
type Capabilities struct {
	Version             string
	SchemaVersion       string
	GradeVersion        string
	Checks              []CheckCapability   // each with its full finding catalogue
	Profiles            []ProfileCapability
	ThirdPartyEndpoints []string
}
```

**If you map vantage's finding identifiers onto your own model, derive the
mapping from `Catalogue` and fail loudly on an unknown identifier.** A mapping
assembled by hand drifts the moment a check is added upstream: the new finding
arrives at run time with nowhere to go and is silently dropped, so your model
quietly stops covering something the library now detects. Each
`CheckCapability` carries the complete `[]finding.Entry` for its check, so the
gap is detectable without a second lookup.

`GradeVersion` identifies the grading algorithm. Grades produced under different
versions must never be compared as though equivalent — trend lines built across
a version change are fiction.

### Reviewing egress before running

Every check declares an `EgressProfile`:

```go
type EgressProfile struct {
	Resolver          bool                // configured DNS resolvers
	TargetNameservers bool                // the target's own nameservers, directly
	TargetHTTPS       bool                // HTTPS to the target
	ThirdParty        []ThirdPartyService // named external services
	Intrusive         bool                // more than a passive observer would do
	Offline           bool                // no egress at all
}
```

The profile is declared alongside the check and the human-readable blast radius
is generated from it, so a check cannot describe itself as touching less than it
does. `Capabilities.ThirdPartyEndpoints` names every host the library may
contact besides your targets.

A deployment policy should be expressed over these classes rather than over
check names. Naming checks in configuration means a newly added intrusive check
runs by default; filtering on declared egress means it is excluded until
somebody consents to what it does.

## Sharing downloaded reference data

Provider address ranges are several megabytes and change slowly. `WithRangeStore`
lets assessments share them:

```go
type RangeStore interface {
	Get(ctx context.Context, url string) (data []byte, at time.Time, ok bool)
	Put(ctx context.Context, url string, data []byte, at time.Time) error
}
```

`Get` returns the content **and when it was obtained**, at any age. Freshness is
the caller's judgement, not the store's — for attribution, stale beats absent:
last week's ranges still name the right operator, whereas returning nothing
would silently retract findings that were correct yesterday. When a fetch fails
and cached data exists, vantage uses the cached data and discloses its age.

There is no package-level cache, and this is not an oversight. A process-wide
memo would let one assessment serve another the results of a third-party
endpoint the second was never authorised to contact — a consent leak no
downstream guard could detect.

## Results

`*finding.Result` is structured data only: no rendering, no formatting. Use
`pkg/report` if you want vantage's renderers, or read the fields directly.

```go
type Result struct {
	SchemaVersion string
	Tool          ToolInfo
	StartedAt     time.Time
	FinishedAt    time.Time
	Resolvers     []string      // which resolvers answered
	Targets       []string
	Summary       Summary
	Findings      []Finding
	Checks        []CheckResult // per-check state — read this
	Errors        []CheckError  // per-check failures — and this
}
```

Call `Finalise()` before rendering or persisting. It sorts findings
deterministically, so two runs against an unchanged domain produce identical
output and a diff shows only genuine change.

Findings carry `Evidence`, and every catalogue entry carries `Remediation` and
`References`. A finding a user cannot verify is a finding they must take on
trust, so evidence is not optional decoration.

**The catalogue is advisory.** Entries describe what to do when something is
*not* right; there is no entry meaning "this control is correctly configured".
Compliance is therefore assessed silence: a check in state `ok` or `not_found`
that raised no findings. Do not look for a positive signal that does not exist —
and do not infer compliance from silence you have not confirmed was *assessed*,
which is why `not_checked` and `check_failed` must stay distinct in your store.

## Cancellation

Both methods take a `context.Context` and honour cancellation. A cancelled run
returns whatever was completed alongside the context error. Record that as an
abandoned assessment, not as a completed one — an interrupted scan that reads as
a clean bill of health is worse than no scan.

## Versioning

`pkg/audit`, `pkg/finding` and `pkg` follow semantic versioning. Finding
identifiers are permanent: once published, an ID is never reassigned or
redefined. New identifiers may appear in a minor release, which is precisely why
a mapping should be derived from `Catalogue` and validated in your CI rather
than maintained by hand.
