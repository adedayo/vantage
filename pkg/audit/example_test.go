package audit_test

import (
	"context"
	"errors"
	"fmt"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/audit"
	"github.com/adedayo/vantage/pkg/finding"
)

// Examples are compiled, so the documented API cannot drift from the real one
// without the build failing. Documentation that is merely proofread rots; the
// README's previous library section documented global setters that had been
// deleted, and nothing caught it.

// ExampleNewAssessor shows the ordinary path: build once, assess many times.
func ExampleNewAssessor() {
	resolver := vantage.NewClient(vantage.ConfigFromEnv())

	assessor, err := audit.NewAssessor(resolver,
		audit.WithVersion("myapp/1.4.0"),
		audit.WithConcurrency(4, 8),
	)
	if err != nil {
		return
	}

	_ = assessor
}

// ExampleNewAssessor_noResolver shows that egress must be supplied. There is no
// ambient default, so a caller cannot accidentally assess through a client
// their scope guard knows nothing about.
func ExampleNewAssessor_noResolver() {
	_, err := audit.NewAssessor(nil)
	fmt.Println(err != nil)
	// Output: true
}

// ExampleAssessor_Assess demonstrates the part consumers most often get wrong:
// a nil error means the run completed, not that every check succeeded.
func ExampleAssessor_Assess() {
	var assessor audit.Assessor // built by NewAssessor

	if assessor == nil {
		return
	}

	result, err := assessor.Assess(context.Background(), audit.Request{
		Targets:   []string{"example.com"},
		Selection: audit.Selection{Profile: audit.ProfileStandard},
	})
	if err != nil {
		// The run itself could not proceed.
		return
	}

	for _, c := range result.Checks {
		switch c.State {
		case finding.StateOK, finding.StateNotFound:
			// A measurement was taken.
		case finding.StateNotChecked, finding.StateCheckFailed:
			// No measurement was taken. Treating this as a pass would report
			// an unmeasured control as a passing one.
		}
	}

	for _, e := range result.Errors {
		// Switch on the code; never parse the message.
		if e.Code == finding.ErrCodeResolverUnreachable && e.Retryable {
			_ = e.RetryAfterSeconds
		}
	}
}

// ExampleRequest_observer shows structured progress. State travels with the
// event so a consumer can show live coverage rather than a percentage, which
// would discard the distinction between a check that found nothing and one
// that could not run.
func ExampleRequest_observer() {
	req := audit.Request{
		Targets: []string{"example.com"},
		Observer: func(p audit.Progress) {
			switch p.Phase {
			case audit.PhaseCheckCompleted:
				fmt.Printf("%s/%s: %s\n", p.Target, p.Check, p.State)
			case audit.PhaseTargetCompleted:
				fmt.Printf("%d/%d targets\n", p.TargetsDone, p.TargetsTotal)
			case audit.PhaseTargetStarted:
				// Ignoring unhandled phases keeps new ones additive.
			}
		},
	}
	_ = req
}

// ExampleAssessor_Catalogue shows the check a consumer should run in CI: every
// identifier the library can raise must have somewhere to go in the consumer's
// own model. A hand-maintained mapping drifts the moment a check is added
// upstream, and the new finding is then silently dropped.
func ExampleAssessor_Catalogue() {
	var assessor audit.Assessor // built by NewAssessor
	if assessor == nil {
		return
	}

	// Obtaining the catalogue makes no network queries.
	caps, err := assessor.Catalogue(context.Background())
	if err != nil {
		return
	}

	myMapping := map[string]string{} // populated by the consumer

	var unmapped []string
	for _, check := range caps.Checks {
		for _, entry := range check.Catalogue {
			if _, ok := myMapping[entry.ID]; !ok {
				unmapped = append(unmapped, entry.ID)
			}
		}
	}
	if len(unmapped) > 0 {
		// Fail loudly rather than dropping findings at run time.
		_ = fmt.Errorf("error: %d unmapped identifiers", len(unmapped))
	}

	// Egress an operator can review before authorising a run.
	for _, check := range caps.Checks {
		_ = check.Egress.Describe()
		_ = check.Egress.Intrusive
	}
	_ = caps.ThirdPartyEndpoints
}

// ExampleSelection shows that a misspelled check name is an error rather than a
// silent no-op: a caller would otherwise believe they had assessed something
// they had not.
func ExampleSelection() {
	_, err := audit.Selection{
		Profile: audit.ProfileEmail,
		Skip:    []string{"nosuchcheck"},
	}.Resolve()
	fmt.Println(err != nil)
	// Output: true
}

// ExampleWithHTTPClient shows that scope enforcement needs both boundaries.
// Guarding DNS alone still discloses the target list to third parties through
// the MTA-STS and takeover paths.
func ExampleWithHTTPClient() {
	var (
		guardedDNS  vantage.Resolver // a consumer's scope-guarded resolver
		guardedHTTP vantage.Doer     // and its scope-guarded HTTP client
	)
	if guardedDNS == nil {
		return
	}

	_, _ = audit.NewAssessor(guardedDNS, audit.WithHTTPClient(guardedHTTP))
}

// ExampleClassifyError shows sentinel matching. Classification tests wrapped
// sentinels before message substrings, so rewording a message cannot change a
// verdict.
func ExampleClassifyError() {
	err := fmt.Errorf("error: dns query failed: %w", vantage.ErrResolverUnreachable)

	fmt.Println(errors.Is(err, vantage.ErrResolverUnreachable))
	fmt.Println(audit.ClassifyError("spf", "example.com", err).Code)
	// Output:
	// true
	// RESOLVER_UNREACHABLE
}
