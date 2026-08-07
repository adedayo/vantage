package audit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/netattr"
)

// Default concurrency limits. They are deliberately modest: the tool queries
// infrastructure that belongs to someone else, and an audit that looks like a
// flood is both rude and likely to be rate-limited into producing wrong
// answers.
const (
	DefaultConcurrency      = 8
	DefaultCheckConcurrency = 6
)

// Runner executes checks against targets.
type Runner struct {
	// Checks to run against every target.
	Checks []Check
	// Resolver is the DNS egress every check queries through. It is required:
	// a runner with no resolver has no sanctioned way to reach the network,
	// and Run refuses rather than falling back to an ambient default.
	//
	// Supplying it per runner is what makes concurrent assessments under
	// different scopes safe. An embedding consumer wraps its own policy around
	// a Client here, and a target outside that policy becomes unreachable at
	// the point of egress rather than merely un-requested.
	Resolver vantage.Resolver
	// HTTP is the egress for checks that fetch a policy file, a page body or a
	// provider range list. Nil uses the library default client; an embedding
	// consumer supplies a guarded one so that an out-of-scope host is refused
	// at the transport rather than merely un-requested.
	HTTP vantage.Doer
	// RangeStore, when non-nil, persists downloaded provider range files so
	// that one download is shared across assessments instead of repeated.
	// It is supplied per runner rather than held globally: the files are
	// fetched through this runner's HTTP client, and a process-wide cache
	// would let one assessment serve another the results of an endpoint the
	// second was never authorised to contact.
	RangeStore netattr.RangeStore
	// Concurrency bounds how many targets are assessed at once.
	Concurrency int
	// CheckConcurrency bounds how many checks run at once per target.
	CheckConcurrency int
	// NoNetwork restricts checks to DNS only.
	NoNetwork bool
	// Hosts are additional names to assess within each target, for the checks
	// that examine individual hosts rather than the zone as a whole. Only
	// names belonging to the target are used.
	Hosts []string
	// Enumerate discovers additional hosts from Certificate Transparency
	// before the checks run, so that names the operator never listed are
	// assessed too. It is opt-in because it queries a third party.
	Enumerate bool
	// Pivot follows certificate co-tenancy outwards, treating registrable
	// domains that share a certificate with a target as further targets and
	// assessing them in full.
	//
	// It is separate from Enumerate because it asks a different question of
	// the operator. Enumerate stays inside a zone whose assessment has already
	// been authorised by naming it; Pivot crosses into domains the operator
	// did not name, which they must have authority over independently.
	Pivot bool
	// PivotDepth and PivotBudget bound the walk. Zero means the ct package
	// defaults.
	PivotDepth, PivotBudget int
	// PivotMaxSANs overrides how large a certificate may be before co-tenancy
	// stops implying common ownership. Zero means the ct package default.
	PivotMaxSANs int
	// ExpectJurisdictions are the ISO 3166-1 alpha-2 countries the operator
	// declares their infrastructure should be in.
	ExpectJurisdictions []string
	// Observer, when non-nil, receives structured progress events as the run
	// advances. It is invoked from multiple goroutines, so implementations
	// must be safe for concurrent use, and it is called while a target's
	// results are being assembled, so it must not block for long.
	Observer func(Progress)
	// Version is the embedding build's version, stamped onto results for
	// provenance. Empty means unknown.
	Version string
}

// emit delivers a progress event if anyone is listening.
func (r *Runner) emit(p Progress) {
	if r.Observer != nil {
		r.Observer(p)
	}
}

// targetResult holds one target's outcome before merging.
type targetResult struct {
	index    int
	target   string
	findings []finding.Finding
	checks   []finding.CheckResult
	errs     []finding.CheckError
}

// Run assesses every target and merges the outcomes into a single result.
//
// A check that fails never aborts the run: its failure is recorded as a
// structured error and the remaining checks continue. A partial answer that
// says which parts are missing is far more useful than no answer at all.
func (r *Runner) Run(ctx context.Context, result *finding.Result, targets ...string) error {
	if len(r.Checks) == 0 {
		return errors.New("error: no checks selected")
	}
	if r.Resolver == nil {
		return errors.New("error: no resolver configured")
	}
	targets = normaliseTargets(targets)
	if len(targets) == 0 {
		return errors.New("error: no targets supplied")
	}

	// Pivoting widens the target list before anything is assessed, so that a
	// discovered sibling receives the same checks as a domain the operator
	// typed. Doing it here rather than per-target keeps the widened set
	// de-duplicated across targets: two domains in one group would otherwise
	// each pull in the same siblings.
	if r.Pivot && !r.NoNetwork {
		targets = r.expandTargets(ctx, result, targets)
	}

	concurrency := r.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make([]targetResult, len(targets))
		done    int
		sem     = make(chan struct{}, concurrency)
	)

	for i, target := range targets {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			out := r.runTarget(ctx, i, target, len(targets))

			mu.Lock()
			results[i] = out
			done++
			completed := done
			mu.Unlock()

			r.emit(Progress{
				Phase:       PhaseTargetCompleted,
				Target:      target,
				TargetsDone: completed, TargetsTotal: len(targets),
				ChecksDone: len(out.checks), ChecksTotal: len(r.Checks),
			})
		}(i, target)
	}
	wg.Wait()

	// Merge in target order so that output does not depend on which goroutine
	// happened to finish first. Determinism is what makes the output diffable.
	for _, out := range results {
		if out.target == "" {
			continue
		}
		result.AddTarget(out.target)
		result.Add(out.findings...)
		result.Checks = append(result.Checks, out.checks...)
		for _, e := range out.errs {
			result.AddError(e)
		}
	}
	result.Resolvers = r.Resolver.Servers()
	result.Finalise()
	result.Summary.Grade = Grade(result.Findings)
	result.Summary.GradeVersion = GradeVersion

	return ctx.Err()
}

// runTarget assesses one target with all selected checks.
func (r *Runner) runTarget(ctx context.Context, index int, target string, totalTargets int) targetResult {
	out := targetResult{index: index, target: target}

	r.emit(Progress{
		Phase:  PhaseTargetStarted,
		Target: target,
		// Targets completed is not yet incremented for this one, so index is
		// not a count; report only the total and let the consumer track its
		// own arithmetic from the completion events.
		TargetsTotal: totalTargets,
		ChecksTotal:  len(r.Checks),
	})

	checkConcurrency := r.CheckConcurrency
	if checkConcurrency <= 0 {
		checkConcurrency = DefaultCheckConcurrency
	}

	// One cache per target: records for different domains share nothing, and a
	// per-target cache keeps memory bounded when assessing a large portfolio.
	t := Target{
		Domain:              target,
		Cache:               NewCacheWithHTTP(r.Resolver, r.HTTP).WithRangeStore(r.RangeStore),
		Hosts:               hostsWithin(target, r.Hosts),
		ExpectJurisdictions: r.ExpectJurisdictions,
		NoNetwork:           r.NoNetwork,
	}

	// Certificate Transparency enumeration runs before the checks rather than
	// as one of them, because its output is an input to the others: the whole
	// point of discovering a name is that takeover and attribution then assess
	// it. Doing it inside a check would make the result depend on the order
	// concurrent checks happened to finish in.
	//
	// A failure here is not fatal. The audit proceeds with the hosts the
	// operator supplied, which is exactly what would have happened without
	// enumeration, and the ct check reports the failure in its own result
	// rather than the whole run stopping because a third party was unavailable.
	if r.Enumerate && !r.NoNetwork {
		if discovered, err := enumerateCT(ctx, t.Cache, target); err == nil {
			t.Hosts = dedupeHosts(append(t.Hosts, analyse.CTHostNames(discovered)...))
		}
	}

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, checkConcurrency)
	)

	for _, check := range r.Checks {
		wg.Add(1)
		go func(check Check) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			name := check.Describe().Name
			outcome, err := check.Run(ctx, t)

			// state is captured under the lock and emitted after releasing it,
			// so that a slow observer cannot serialise the whole target.
			var state finding.State

			mu.Lock()
			switch {
			case err != nil && errors.Is(err, vantage.ErrNotFound):
				state = finding.StateNotFound
				out.checks = append(out.checks, finding.CheckResult{
					Check: name, Target: target, State: finding.StateNotFound,
				})
				out.findings = append(out.findings, outcome.Findings...)
			case err != nil:
				// The outcome's records are kept even though the check
				// failed. A check that reports "could not complete" without
				// showing what it attempted gives a reader no way to tell a
				// blocked network from a broken tool, and for checks like
				// AXFR the list of servers tried is the entire justification
				// for the failure.
				state = finding.StateCheckFailed
				out.checks = append(out.checks, finding.CheckResult{
					Check: name, Target: target, State: finding.StateCheckFailed,
					Records: outcome.Records,
				})
				out.errs = append(out.errs, ClassifyError(name, target, err))
			default:
				state = outcome.State
				if state == "" {
					state = finding.StateOK
				}
				out.checks = append(out.checks, finding.CheckResult{
					Check: name, Target: target, State: state, Records: outcome.Records,
				})
				out.findings = append(out.findings, outcome.Findings...)
			}
			checksDone := len(out.checks)
			mu.Unlock()

			r.emit(Progress{
				Phase:  PhaseCheckCompleted,
				Target: target, Check: name, State: state,
				TargetsTotal: totalTargets,
				ChecksDone:   checksDone, ChecksTotal: len(r.Checks),
			})
		}(check)
	}
	wg.Wait()

	return out
}

// normaliseTargets trims, lower-cases and de-duplicates targets while
// preserving the caller's ordering.
func normaliseTargets(targets []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		t = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(t), ".")))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// ClassifyError converts a check failure into a structured error with a stable
// code and a retry hint, so an automated consumer never has to interpret the
// wording of a message.
//
// Classification is by wrapped sentinel first and message substring only as a
// fallback. The substring arm covers errors arriving from dependencies that
// know nothing of our sentinels; anything raised within vantage should match on
// the sentinel, so that rewording a message can never change a verdict.
//
// Ordering matters. Cancellation and deadlines are tested before transport
// failures because a timeout surfaces wrapped in a resolver error, and the
// actionable fact is that the caller's budget ran out, not that a server was
// unreachable. Out-of-scope is tested before everything because it means no
// attempt was made at all.
func ClassifyError(check, target string, err error) finding.CheckError {
	msg := err.Error()
	code := finding.ErrCodeInternal
	retryable := false

	switch {
	case errors.Is(err, vantage.ErrOutOfScope):
		code = finding.ErrCodeOutOfScope
	case errors.Is(err, vantage.ErrNetworkDisabled):
		code = finding.ErrCodeNetworkDisabled
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		code, retryable = finding.ErrCodeTimeout, true
	case errors.Is(err, vantage.ErrResolverUnreachable) ||
		strings.Contains(msg, "dns query failed") ||
		strings.Contains(msg, "no DNS resolvers") ||
		strings.Contains(msg, "no resolvers"):
		code, retryable = finding.ErrCodeResolverUnreachable, true
	case errors.Is(err, vantage.ErrNotFound) || strings.Contains(msg, "not found"):
		code = finding.ErrCodeNotFound
	case errors.Is(err, vantage.ErrInvalidRecord) ||
		strings.Contains(msg, "invalid") || strings.Contains(msg, "malformed"):
		code = finding.ErrCodeInvalidRecord
	}

	e := finding.CheckError{
		Check: check, Target: target, Code: code, Message: msg, Retryable: retryable,
	}
	if retryable {
		e.RetryAfterSeconds = 5
	}
	return e
}

// SortedCheckNames returns the names of the runner's checks, for reporting.
func (r *Runner) SortedCheckNames() []string {
	names := make([]string, 0, len(r.Checks))
	for _, c := range r.Checks {
		names = append(names, c.Describe().Name)
	}
	sort.Strings(names)
	return names
}

// String describes the runner's configuration, for progress and debug output.
func (r *Runner) String() string {
	return fmt.Sprintf("runner[checks=%s concurrency=%d check-concurrency=%d]",
		strings.Join(r.SortedCheckNames(), ","), r.Concurrency, r.CheckConcurrency)
}
