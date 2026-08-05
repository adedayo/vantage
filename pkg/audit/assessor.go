package audit

import (
	"context"
	"fmt"
	"sort"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/netattr"
)

// Phase names a point in a run at which progress is reported.
type Phase string

const (
	// PhaseTargetStarted fires once per target, before any of its checks run.
	PhaseTargetStarted Phase = "target-started"
	// PhaseCheckCompleted fires once per check per target, carrying the state
	// that check settled on.
	PhaseCheckCompleted Phase = "check-completed"
	// PhaseTargetCompleted fires once per target, after all its checks.
	PhaseTargetCompleted Phase = "target-completed"
)

// Progress is a single observation about a run's advancement.
//
// It is a struct rather than a set of positional arguments because the
// interesting events differ in shape, and because a consumer driving a user
// interface needs to distinguish "this check finished and found nothing" from
// "this check finished and could not run". Collapsing those into a percentage
// throws away the only part a person watching actually needs.
type Progress struct {
	// Phase says which kind of event this is. Consumers should switch on it
	// and ignore phases they do not handle, so that new phases are additive.
	Phase Phase
	// Target is the domain being assessed. Always set.
	Target string
	// Check is the check that completed. Set only for PhaseCheckCompleted.
	Check string
	// State is the outcome the check settled on. Set only for
	// PhaseCheckCompleted. It is carried here so a consumer can show live
	// coverage without waiting for the whole run to finish.
	State finding.State
	// TargetsDone and TargetsTotal track overall advancement.
	TargetsDone, TargetsTotal int
	// ChecksDone and ChecksTotal track advancement within the current target.
	// They are meaningless across targets, since targets run concurrently.
	ChecksDone, ChecksTotal int
}

// Request is one assessment, fully specified.
//
// Everything that shapes an assessment lives here rather than in ambient
// configuration, so that two concurrent requests under different scopes cannot
// interfere with one another.
type Request struct {
	// Targets are the domains to assess.
	Targets []string
	// Selection chooses the checks. The zero value resolves to the standard
	// profile, which is the sensible default for a caller who has expressed no
	// opinion.
	Selection Selection
	// Hosts are additional names within the targets to assess, for the checks
	// that examine individual hosts. Nothing is ever guessed to fill this.
	Hosts []string
	// Enumerate discovers further hosts from Certificate Transparency. It is
	// opt-in because it queries a third party.
	Enumerate bool
	// ExpectJurisdictions are the ISO 3166-1 alpha-2 countries the operator
	// declares their infrastructure should be in. Empty means no expectation
	// was stated, and the jurisdiction rule is then not evaluated.
	ExpectJurisdictions []string
	// Concurrency and CheckConcurrency bound parallelism. Zero means default.
	Concurrency, CheckConcurrency int
	// Observer, when non-nil, receives progress. It is called from multiple
	// goroutines and must be safe for concurrent use.
	Observer func(Progress)
}

// CheckCapability is what one check declares about itself, for a consumer
// deciding whether to invoke it.
type CheckCapability struct {
	Description
	// Catalogue is the full entry for every finding the check can raise, so a
	// consumer can build its own mapping without a second lookup and without
	// hard-coding identifiers this library owns.
	Catalogue []finding.Entry
}

// ProfileCapability describes a profile and its membership.
type ProfileCapability struct {
	Name    string   `json:"name"`
	Summary string   `json:"summary"`
	Checks  []string `json:"checks"`
}

// Capabilities is the machine-readable manifest of everything this library can
// assess, what each assessment costs and what it touches.
//
// It exists so that an embedding consumer can be built against declarations
// rather than against a hard-coded list. Trawl needs to map every finding this
// library can raise onto its own signal registry, and a registry assembled by
// hand drifts the moment a check is added upstream: the new finding arrives at
// run time with nowhere to go and is silently dropped. Fetching the catalogue
// means the consumer can instead detect the gap and fail loudly.
type Capabilities struct {
	// Version is the library version, for provenance on stored results.
	Version string `json:"version"`
	// SchemaVersion is the result schema the library emits.
	SchemaVersion string `json:"schema_version"`
	// GradeVersion identifies the grading algorithm, so that grades stored
	// under different versions are never compared as though equivalent.
	GradeVersion string `json:"grade_version"`
	// Checks is every registered check with its full finding catalogue.
	Checks []CheckCapability `json:"checks"`
	// Profiles is every selectable profile with its membership.
	Profiles []ProfileCapability `json:"profiles"`
	// ThirdPartyEndpoints are the hosts this library may contact besides the
	// targets themselves, so an operator can review egress before running.
	ThirdPartyEndpoints []string `json:"third_party_endpoints"`
}

// Assessor is the embedding contract.
//
// It is deliberately narrow. A consumer needs to know what the library can do
// and to ask it to do some of that; everything else — resolvers, timeouts,
// concurrency — is constructor-time configuration, not part of the calling
// surface. Keeping it to two methods also makes it trivial to fake in a
// consumer's own tests, which is what stops those tests reaching the network.
type Assessor interface {
	// Catalogue reports what this library can assess.
	Catalogue(ctx context.Context) (Capabilities, error)
	// Assess runs the request and returns a populated result.
	//
	// A check that fails never aborts the assessment: the failure is recorded
	// as a structured error against that check and the rest continue. A nil
	// error therefore means the run completed, not that everything succeeded;
	// callers must inspect the result's per-check states and errors.
	Assess(ctx context.Context, req Request) (*finding.Result, error)
}

// Assert at compile time that the runner satisfies the contract, so that a
// change to either side fails the build rather than a downstream consumer's.
var _ Assessor = (*Runner)(nil)

// Catalogue implements Assessor.
func (r *Runner) Catalogue(ctx context.Context) (Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return Capabilities{}, err
	}
	if err := ValidateRegistry(); err != nil {
		return Capabilities{}, err
	}

	caps := Capabilities{
		Version:       r.version(),
		SchemaVersion: finding.SchemaVersion,
		GradeVersion:  GradeVersion,
	}

	for _, desc := range Descriptions() {
		entries := make([]finding.Entry, 0, len(desc.Findings))
		for _, id := range desc.Findings {
			if e, ok := finding.Lookup(id); ok {
				entries = append(entries, e)
			}
		}
		caps.Checks = append(caps.Checks, CheckCapability{Description: desc, Catalogue: entries})
	}

	for _, name := range Profiles() {
		p := Profile(name)
		members := profileMembers[p]
		if members == nil {
			// A nil membership means "everything registered". Resolving it
			// here keeps the manifest honest as checks are added.
			members = Names()
		}
		checks := append([]string(nil), members...)
		sort.Strings(checks)
		caps.Profiles = append(caps.Profiles, ProfileCapability{
			Name: name, Summary: p.Summary(), Checks: checks,
		})
	}

	caps.ThirdPartyEndpoints = ThirdPartyEndpointHosts()
	return caps, nil
}

// Assess implements Assessor.
func (r *Runner) Assess(ctx context.Context, req Request) (*finding.Result, error) {
	checks, err := req.Selection.Resolve()
	if err != nil {
		return nil, err
	}

	run := &Runner{
		Checks:              checks,
		Resolver:            r.Resolver,
		HTTP:                r.HTTP,
		RangeStore:          r.RangeStore,
		Concurrency:         pick(req.Concurrency, r.Concurrency),
		CheckConcurrency:    pick(req.CheckConcurrency, r.CheckConcurrency),
		NoNetwork:           req.Selection.NoNetwork,
		Hosts:               req.Hosts,
		Enumerate:           req.Enumerate,
		ExpectJurisdictions: req.ExpectJurisdictions,
		Observer:            req.Observer,
		Version:             r.Version,
	}

	result := finding.NewResult("vantage", run.version())
	if err := run.Run(ctx, result, req.Targets...); err != nil {
		return result, err
	}
	return result, nil
}

// version reports the library version to stamp on results, falling back to a
// marker rather than an empty string. Provenance that says "unknown" is
// honest; provenance that says nothing looks like a serialisation bug.
func (r *Runner) version() string {
	if r.Version != "" {
		return r.Version
	}
	return "unknown"
}

// pick returns the first positive value, so a per-request override wins over
// the assessor's default and zero means "unset" at both levels.
func pick(override, fallback int) int {
	if override > 0 {
		return override
	}
	return fallback
}

// NewAssessor builds an Assessor from a resolver and options.
//
// The resolver is a required argument rather than an option because there is no
// safe default for it. An assessor that silently invented its own egress would
// defeat the scope guarding an embedding consumer wraps around it.
func NewAssessor(resolver vantage.Resolver, opts ...Option) (Assessor, error) {
	if resolver == nil {
		return nil, fmt.Errorf("error: a resolver is required")
	}
	a := &Runner{Resolver: resolver}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Option configures an Assessor at construction.
type Option func(*Runner)

// WithVersion stamps results with the embedding build's version.
func WithVersion(v string) Option {
	return func(r *Runner) { r.Version = v }
}

// WithRangeStore shares downloaded provider ranges across assessments.
func WithRangeStore(store netattr.RangeStore) Option {
	return func(r *Runner) { r.RangeStore = store }
}

// WithHTTPClient sets the HTTP egress for checks that fetch over HTTP. Supply
// a guarded client to enforce scope at the transport.
func WithHTTPClient(hc vantage.Doer) Option {
	return func(r *Runner) { r.HTTP = hc }
}

// WithConcurrency sets default parallelism across targets and within a target.
func WithConcurrency(targets, checks int) Option {
	return func(r *Runner) {
		r.Concurrency, r.CheckConcurrency = targets, checks
	}
}
