package audit

import (
	"time"

	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	vantage "github.com/adedayo/vantage/pkg"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/finding"
)

// testClient is the resolver tests query through. Tests that stand up a local
// DNS server replace it; the rest point at an address nothing answers on,
// which is what the cache tests want — they assert on how often a question is
// asked, not on the answer it gets.
//
// Injection is what makes this possible: the old package-level setters meant
// one test's resolver configuration was every test's, so these could not run
// in parallel and a forgotten reset leaked into unrelated cases.
var testClient vantage.Resolver = vantage.NewClient(vantage.Config{
	Servers:      []string{"127.0.0.1:1"},
	QueryTimeout: 10 * time.Millisecond,
	TotalTimeout: 50 * time.Millisecond,
})

// egressFor builds a profile equivalent to a coarse Network value, so that
// tests written against the classification stay readable now that the profile
// is the thing actually declared.
func egressFor(networks ...Network) EgressProfile {
	var e EgressProfile
	for _, n := range networks {
		switch n {
		case NetworkDNS:
			e.Resolver = true
		case NetworkHTTPS:
			e.TargetHTTPS = true
		case NetworkThirdParty:
			e.ThirdParty = []ThirdPartyService{ServiceCertSpotter}
		case NetworkNone:
			e.Offline = true
		}
	}
	return e
}

// stub builds a check that records its invocation and returns a fixed outcome.
func stub(name string, network Network, out Outcome, err error) Check {
	return CheckFunc{
		Description: Description{
			Name:           name,
			Summary:        name + " stub",
			Egress:         egressFor(network),
			TypicalQueries: 1,
		},
		Fn: func(context.Context, Target) (Outcome, error) { return out, err },
	}
}

// withRegistry swaps in a clean registry for the duration of a test, so that
// registry assertions never depend on what the production init() happens to
// have registered.
func withRegistry(t *testing.T, checks ...Check) {
	t.Helper()
	registryMu.Lock()
	saved := registry
	registry = map[string]Check{}
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})
	for _, c := range checks {
		Register(c)
	}
}

func TestProductionRegistryIsValid(t *testing.T) {
	// The real registry must be self-consistent: every declared finding ID has
	// to exist in the catalogue, or the tool would promise detail it cannot
	// deliver.
	require.NoError(t, ValidateRegistry())
	assert.NotEmpty(t, Names())
}

func TestEveryProfileMemberIsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, n := range Names() {
		registered[n] = true
	}
	for profile, members := range profileMembers {
		for _, m := range members {
			assert.Truef(t, registered[m],
				"profile %q names unregistered check %q", profile, m)
		}
		if members != nil {
			assert.NotEmptyf(t, profileSummaries[profile],
				"profile %q has no summary", profile)
		}
	}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	withRegistry(t, stub("a", NetworkDNS, Outcome{}, nil))
	assert.Panics(t, func() { Register(stub("a", NetworkDNS, Outcome{}, nil)) })
}

func TestLookupAndNames(t *testing.T) {
	withRegistry(t,
		stub("zulu", NetworkDNS, Outcome{}, nil),
		stub("alpha", NetworkDNS, Outcome{}, nil),
	)
	// Names must be sorted so that output is reproducible run to run, which is
	// a prerequisite for the drift detection planned in spec 013.
	assert.Equal(t, []string{"alpha", "zulu"}, Names())

	c, ok := Lookup("alpha")
	require.True(t, ok)
	assert.Equal(t, "alpha", c.Describe().Name)

	_, ok = Lookup("missing")
	assert.False(t, ok)
}

func TestDescriptionRequiresNetwork(t *testing.T) {
	assert.False(t, Description{Egress: egressFor(NetworkDNS)}.RequiresNetwork())
	assert.False(t, Description{Egress: egressFor(NetworkNone)}.RequiresNetwork())
	assert.True(t, Description{Egress: egressFor(NetworkDNS, NetworkHTTPS)}.RequiresNetwork())
	assert.True(t, Description{Egress: egressFor(NetworkThirdParty)}.RequiresNetwork())
}

func TestDescriptionExcludedByNoNetwork(t *testing.T) {
	// Using egress is not the same as depending on it. A check that still
	// detects a missing control from DNS alone must survive --no-network,
	// otherwise the run reports silence as safety.
	assert.False(t, Description{Egress: egressFor(NetworkDNS)}.ExcludedByNoNetwork())
	assert.True(t, Description{Egress: egressFor(NetworkDNS, NetworkHTTPS)}.ExcludedByNoNetwork())
	assert.False(t, Description{
		Egress:                 egressFor(NetworkDNS, NetworkHTTPS),
		DegradesWithoutNetwork: true,
	}.ExcludedByNoNetwork())
}

// TestMTASTSSurvivesNoNetwork pins the real registered check, not a stub. The
// bug this guards against was that --no-network removed MTA-STS entirely, so a
// domain publishing no policy at all was reported clean.
func TestMTASTSSurvivesNoNetwork(t *testing.T) {
	desc := mtastsCheck().Describe()
	assert.True(t, desc.RequiresNetwork(), "the policy fetch is HTTPS egress and must be declared")
	assert.False(t, desc.ExcludedByNoNetwork(), "MTA-STS must still run DNS-only under --no-network")
}

func TestParseProfile(t *testing.T) {
	for _, name := range Profiles() {
		p, err := ParseProfile(name)
		require.NoErrorf(t, err, "profile %q should parse", name)
		assert.NotEmpty(t, p.Summary())
	}

	p, err := ParseProfile("  QUICK ")
	require.NoError(t, err)
	assert.Equal(t, ProfileQuick, p)

	_, err = ParseProfile("nonsense")
	require.Error(t, err)
	// The message must list the alternatives; an agent recovering from a bad
	// argument should not have to guess.
	assert.Contains(t, err.Error(), "quick")
}

func TestSelectionResolve(t *testing.T) {
	withRegistry(t,
		stub("spf", NetworkDNS, Outcome{}, nil),
		stub("dmarc", NetworkDNS, Outcome{}, nil),
		stub("mtasts", NetworkHTTPS, Outcome{}, nil),
	)

	names := func(cs []Check) []string {
		var out []string
		for _, c := range cs {
			out = append(out, c.Describe().Name)
		}
		return out
	}

	t.Run("defaults to standard", func(t *testing.T) {
		cs, err := Selection{}.Resolve()
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"spf", "dmarc", "mtasts"}, names(cs))
	})

	t.Run("only replaces the profile", func(t *testing.T) {
		cs, err := Selection{Profile: ProfileQuick, Only: []string{"mtasts"}}.Resolve()
		require.NoError(t, err)
		assert.Equal(t, []string{"mtasts"}, names(cs))
	})

	t.Run("skip is applied last", func(t *testing.T) {
		cs, err := Selection{Only: []string{"spf", "dmarc"}, Skip: []string{"spf"}}.Resolve()
		require.NoError(t, err)
		assert.Equal(t, []string{"dmarc"}, names(cs))
	})

	t.Run("no-network drops egress checks", func(t *testing.T) {
		cs, err := Selection{NoNetwork: true}.Resolve()
		require.NoError(t, err)
		assert.NotContains(t, names(cs), "mtasts")
	})

	t.Run("unknown names are rejected", func(t *testing.T) {
		_, err := Selection{Only: []string{"typo"}}.Resolve()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "typo")

		_, err = Selection{Skip: []string{"typo"}}.Resolve()
		require.Error(t, err)
	})

	t.Run("empty selection is an error", func(t *testing.T) {
		_, err := Selection{Only: []string{"spf"}, Skip: []string{"spf"}}.Resolve()
		require.Error(t, err)
	})
}

func TestRunnerMergesDeterministically(t *testing.T) {
	withRegistry(t)
	check := CheckFunc{
		Description: Description{Name: "stub", Egress: egressFor(NetworkDNS)},
		Fn: func(_ context.Context, tg Target) (Outcome, error) {
			return Outcome{State: finding.StateOK, Records: []string{"r:" + tg.Domain}}, nil
		},
	}

	targets := []string{"c.example", "a.example", "b.example"}
	var first []finding.CheckResult
	for i := 0; i < 5; i++ {
		r := &Runner{Resolver: testClient, Checks: []Check{check}, Concurrency: 4}
		res := finding.NewResult("vantage", "test")
		require.NoError(t, r.Run(context.Background(), res, targets...))
		res.Finalise()
		if i == 0 {
			first = res.Checks
			continue
		}
		// Concurrency must not leak into the output: identical inputs have to
		// produce byte-identical results, otherwise baselining is impossible.
		assert.Equal(t, first, res.Checks)
	}
	require.Len(t, first, 3)
	assert.Equal(t, []string{"a.example", "b.example", "c.example"},
		[]string{first[0].Target, first[1].Target, first[2].Target})
}

func TestRunnerIsolatesCheckFailures(t *testing.T) {
	withRegistry(t)
	good := stub("good", NetworkDNS, Outcome{State: finding.StateOK, Records: []string{"ok"}}, nil)
	bad := stub("bad", NetworkDNS, Outcome{}, errors.New("i/o timeout"))

	r := &Runner{Resolver: testClient, Checks: []Check{good, bad}, CheckConcurrency: 2}
	res := finding.NewResult("vantage", "test")
	require.NoError(t, r.Run(context.Background(), res, "example.com"))
	res.Finalise()

	// One failing check must never suppress the others: a partial answer that
	// says what is missing beats no answer at all.
	require.Len(t, res.Errors, 1)
	assert.Equal(t, "bad", res.Errors[0].Check)
	assert.Equal(t, finding.ErrCodeTimeout, res.Errors[0].Code)
	assert.True(t, res.Errors[0].Retryable)

	states := map[string]finding.State{}
	for _, c := range res.Checks {
		states[c.Check] = c.State
	}
	assert.Equal(t, finding.StateOK, states["good"])
	assert.Equal(t, finding.StateCheckFailed, states["bad"])
}

func TestRunnerRejectsEmptyInput(t *testing.T) {
	res := finding.NewResult("vantage", "test")
	require.Error(t, (&Runner{}).Run(context.Background(), res, "example.com"))

	check := stub("stub", NetworkDNS, Outcome{}, nil)
	require.Error(t, (&Runner{Resolver: testClient, Checks: []Check{check}}).Run(context.Background(), res))
	require.Error(t, (&Runner{Resolver: testClient, Checks: []Check{check}}).Run(context.Background(), res, "  "))
}

func TestRunnerReportsProgress(t *testing.T) {
	var (
		mu    sync.Mutex
		seen  int
		total int
	)
	r := &Runner{
		Resolver:    testClient,
		Checks:      []Check{stub("stub", NetworkDNS, Outcome{State: finding.StateOK}, nil)},
		Concurrency: 3,
		Observer: func(p Progress) {
			if p.Phase != PhaseTargetCompleted {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			seen++
			total = p.TargetsTotal
		},
	}
	res := finding.NewResult("vantage", "test")
	require.NoError(t, r.Run(context.Background(), res, "a.example", "b.example", "c.example"))
	assert.Equal(t, 3, seen)
	assert.Equal(t, 3, total)
}

// TestRunnerReportsPerCheckProgress pins the granularity an embedding consumer
// needs. Reporting only on target completion is useless for a single target,
// which is the common case: the user would watch a frozen bar until the whole
// assessment finished.
func TestRunnerReportsPerCheckProgress(t *testing.T) {
	var (
		mu       sync.Mutex
		states   = map[string]finding.State{}
		started  int
		finished int
	)
	r := &Runner{
		Resolver: testClient,
		Checks: []Check{
			stub("ok", NetworkDNS, Outcome{State: finding.StateOK}, nil),
			stub("missing", NetworkDNS, Outcome{}, vantage.ErrNotFound),
			stub("broken", NetworkDNS, Outcome{}, errors.New("boom")),
		},
		Observer: func(p Progress) {
			mu.Lock()
			defer mu.Unlock()
			switch p.Phase {
			case PhaseTargetStarted:
				started++
			case PhaseCheckCompleted:
				states[p.Check] = p.State
			case PhaseTargetCompleted:
				finished++
			}
		},
	}
	res := finding.NewResult("vantage", "test")
	require.NoError(t, r.Run(context.Background(), res, "example.com"))

	assert.Equal(t, 1, started)
	assert.Equal(t, 1, finished)
	// The four-state distinction has to survive into progress. A consumer
	// showing "2 of 3 done" while one of them silently failed is reporting
	// coverage it does not have.
	assert.Equal(t, map[string]finding.State{
		"ok":      finding.StateOK,
		"missing": finding.StateNotFound,
		"broken":  finding.StateCheckFailed,
	}, states)
}

func TestNormaliseTargets(t *testing.T) {
	got := normaliseTargets([]string{"  Example.COM ", "example.com", "", "b.example.", "  "})
	// De-duplication has to be case- and trailing-dot-insensitive, or a bulk
	// input file would be billed twice for the same domain.
	assert.Equal(t, []string{"example.com", "b.example"}, got)
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		msg       string
		code      finding.ErrorCode
		retryable bool
	}{
		{"context deadline exceeded", finding.ErrCodeTimeout, true},
		{"read udp: i/o timeout", finding.ErrCodeTimeout, true},
		{"dns query failed", finding.ErrCodeResolverUnreachable, true},
		{"no resolvers configured", finding.ErrCodeResolverUnreachable, true},
		{"record not found", finding.ErrCodeNotFound, false},
		{"malformed record", finding.ErrCodeInvalidRecord, false},
		{"something unexpected", finding.ErrCodeInternal, false},
	}
	for _, c := range cases {
		t.Run(c.msg, func(t *testing.T) {
			got := ClassifyError("spf", "example.com", errors.New(c.msg))
			assert.Equal(t, c.code, got.Code)
			assert.Equal(t, c.retryable, got.Retryable)
			assert.Equal(t, "spf", got.Check)
			assert.Equal(t, "example.com", got.Target)
			if c.retryable {
				assert.Positive(t, got.RetryAfterSeconds,
					"a retryable error must tell the caller how long to wait")
			}
		})
	}
}

// TestClassifyErrorUsesSentinels pins classification to the wrapped sentinel
// rather than the message. Every message here is deliberately worded so that
// the substring fallback would reach the wrong answer, so the test fails if
// somebody removes the sentinel arms and relies on wording again.
func TestClassifyErrorUsesSentinels(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		code      finding.ErrorCode
		retryable bool
	}{
		{
			"out of scope beats everything",
			fmt.Errorf("refused: %w", vantage.ErrOutOfScope),
			finding.ErrCodeOutOfScope, false,
		},
		{
			"network disabled is not a failure to reach the network",
			fmt.Errorf("https egress withheld: %w", vantage.ErrNetworkDisabled),
			finding.ErrCodeNetworkDisabled, false,
		},
		{
			"resolver unreachable",
			fmt.Errorf("could not reach: %w", vantage.ErrResolverUnreachable),
			finding.ErrCodeResolverUnreachable, true,
		},
		{
			"not found is a negative result, not a failure",
			fmt.Errorf("no record: %w", vantage.ErrNotFound),
			finding.ErrCodeNotFound, false,
		},
		{
			"invalid record",
			fmt.Errorf("could not parse: %w", vantage.ErrInvalidRecord),
			finding.ErrCodeInvalidRecord, false,
		},
		{
			// A timeout arrives wrapped inside a resolver error. The caller's
			// budget expiring is the actionable fact, so it must win.
			"deadline inside a resolver error classifies as timeout",
			fmt.Errorf("%w: %w", vantage.ErrResolverUnreachable, context.DeadlineExceeded),
			finding.ErrCodeTimeout, true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyError("spf", "example.com", c.err)
			assert.Equal(t, c.code, got.Code)
			assert.Equal(t, c.retryable, got.Retryable)
		})
	}
}

// TestOutOfScopeIsNeverRetryable guards a safety property. A scope refusal is
// the caller's own policy speaking, so retrying cannot change the outcome and
// advertising it as retryable would invite a consumer to hammer a target it
// has already been told it may not touch.
func TestOutOfScopeIsNeverRetryable(t *testing.T) {
	got := ClassifyError("ct", "example.com",
		fmt.Errorf("scope guard: %w", vantage.ErrOutOfScope))
	assert.False(t, got.Retryable)
	assert.Zero(t, got.RetryAfterSeconds)
}

// graded builds n findings at a severity and confidence, for grading tests.
func graded(n int, s finding.Severity, c finding.Confidence) []finding.Finding {
	out := make([]finding.Finding, 0, n)
	for range n {
		out = append(out, finding.Finding{Severity: s, Confidence: c})
	}
	return out
}

func TestGrade(t *testing.T) {
	high := finding.ConfidenceHigh
	assert.Equal(t, "A", Grade(nil))
	assert.Equal(t, "A", Grade(graded(9, finding.SeverityInfo, high)))
	assert.Equal(t, "B", Grade(graded(1, finding.SeverityLow, high)))
	assert.Equal(t, "B", Grade(graded(1, finding.SeverityMedium, high)))
	assert.Equal(t, "C", Grade(graded(3, finding.SeverityMedium, high)))
	assert.Equal(t, "D", Grade(graded(1, finding.SeverityHigh, high)))
	assert.Equal(t, "E", Grade(graded(3, finding.SeverityHigh, high)))
	// A single critical outranks everything: one exploitable weakness is
	// enough to fail the whole domain.
	assert.Equal(t, "F", Grade(append(
		graded(1, finding.SeverityCritical, high),
		graded(1, finding.SeverityHigh, high)...)))

	for _, g := range []string{"A", "B", "C", "D", "E", "F"} {
		assert.NotEmptyf(t, GradeDescription(g), "grade %s needs a description", g)
	}
}

// A keyword guess about a hostname must not weigh as heavily as an unsigned
// delegation the resolver proved. Grading on severity alone discarded the
// confidence the catalogue records, at the one point where it mattered most.
func TestGradeWeighsConfidence(t *testing.T) {
	// Three deterministic mediums are a C; three heuristic mediums are not.
	assert.Equal(t, "C", Grade(graded(3, finding.SeverityMedium, finding.ConfidenceHigh)))
	assert.Equal(t, "B", Grade(graded(3, finding.SeverityMedium, finding.ConfidenceMedium)))

	// Low confidence demotes two bands, so a medium stops counting entirely.
	assert.Equal(t, "A", Grade(graded(9, finding.SeverityMedium, finding.ConfidenceLow)))
}

// Demotion, not exclusion: a serious finding we are less sure of still counts
// for something, and must not vanish from the grade altogether.
func TestGradeDemotesRatherThanIgnoresUncertainFindings(t *testing.T) {
	assert.Equal(t, "D", Grade(graded(1, finding.SeverityHigh, finding.ConfidenceHigh)))
	assert.Equal(t, "B", Grade(graded(1, finding.SeverityHigh, finding.ConfidenceMedium)))

	// A low-confidence critical lands at medium and is still visible.
	assert.Equal(t, "B", Grade(graded(1, finding.SeverityCritical, finding.ConfidenceLow)))
	// Three of them are enough to warrant a C.
	assert.Equal(t, "C", Grade(graded(3, finding.SeverityCritical, finding.ConfidenceLow)))
}

// A risk the operator has accepted must not keep driving the grade down.
func TestGradeIgnoresSuppressedFindings(t *testing.T) {
	findings := graded(3, finding.SeverityCritical, finding.ConfidenceHigh)
	for i := range findings {
		findings[i].Suppressed = true
	}
	assert.Equal(t, "A", Grade(findings))
}

// The grade is adjusted by confidence; the reported severities are not. A
// reader must still see what was actually found.
func TestGradeDoesNotAlterReportedSeverities(t *testing.T) {
	f := finding.New("SURF-CT-002", "example.com")
	require.Equal(t, "medium", f.Severity.String())

	r := finding.NewResult("vantage", "test")
	r.Add(f, f, f)
	r.Finalise()
	r.Summary.Grade = Grade(r.Findings)

	assert.Equal(t, 3, r.Summary.Medium, "counts report severity, not grading weight")
	assert.Equal(t, "B", r.Summary.Grade, "three heuristic findings do not make a C")
}

func TestCacheDeduplicatesConcurrentQueries(t *testing.T) {
	c := NewCache(testClient)

	// Prime the cache through the public surface would require a resolver, so
	// exercise de-duplication directly: many goroutines asking the identical
	// question must collapse to one lookup.
	const goroutines = 32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = c.LookupTXT(context.Background(), "invalid.")
		}()
	}
	wg.Wait()

	hits, misses := c.Stats()
	assert.Equal(t, 1, misses, "the same question must only be asked once")
	assert.Equal(t, goroutines-1, hits)
}

func TestCacheSeparatesQuestions(t *testing.T) {
	c := NewCache(testClient)
	for i := 0; i < 3; i++ {
		_, _, _ = c.LookupTXT(context.Background(), fmt.Sprintf("q%d.invalid.", i))
	}
	hits, misses := c.Stats()
	assert.Equal(t, 3, misses)
	assert.Zero(t, hits)
}

// TestCacheJoinsSplitTXTStrings guards a false-positive source. A TXT record
// over 255 bytes travels as several strings; treating them as separate records
// splits a 2048-bit DKIM key into unparseable fragments and makes one long SPF
// record look like the duplicate that RFC 7208 says is a PermError.
func TestCacheJoinsSplitTXTStrings(t *testing.T) {
	tests := map[string]struct {
		strings []string
		want    string
	}{
		"single string is unchanged": {
			strings: []string{"v=spf1 -all"},
			want:    "v=spf1 -all",
		},
		"split record is rejoined verbatim": {
			strings: []string{"v=spf1 ip4:192.0.2.0/24 ", "include:example.net ", "-all"},
			want:    "v=spf1 ip4:192.0.2.0/24 include:example.net -all",
		},
		"no separator is introduced": {
			strings: []string{"v=DKIM1; k=rsa; p=AAAA", "BBBB", "CCCC"},
			want:    "v=DKIM1; k=rsa; p=AAAABBBBCCCC",
		},
		"empty record": {strings: nil, want: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, joinTXT(&dns.TXT{Txt: tc.strings}))
		})
	}
}

func TestRunnerString(t *testing.T) {
	r := &Runner{Resolver: testClient, Checks: []Check{stub("b", NetworkDNS, Outcome{}, nil), stub("a", NetworkDNS, Outcome{}, nil)}}
	assert.Equal(t, []string{"a", "b"}, r.SortedCheckNames())
	assert.Contains(t, r.String(), "a")
}
