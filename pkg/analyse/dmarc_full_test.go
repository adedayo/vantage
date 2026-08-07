package analyse

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vantage "github.com/adedayo/vantage/pkg"
)

// fakeDMARCResolver serves TXT records from a map.
type fakeDMARCResolver struct {
	txt     map[string][]string
	queries []string
}

func (f *fakeDMARCResolver) TXT(_ context.Context, name string) ([]string, error) {
	f.queries = append(f.queries, name)
	records, ok := f.txt[name]
	if !ok {
		return nil, fmt.Errorf("error: not found")
	}
	return records, nil
}

func TestOrganisationalDomain(t *testing.T) {
	tests := map[string]struct {
		domain string
		suffix string
		want   string
	}{
		"subdomain reduces to registrable domain": {
			domain: "mail.corp.example.com", suffix: "com", want: "example.com",
		},
		"registrable domain is unchanged": {
			domain: "example.com", suffix: "com", want: "example.com",
		},
		"multi-label suffix": {
			domain: "www.example.co.uk", suffix: "co.uk", want: "example.co.uk",
		},
		"case and trailing dot are normalised": {
			domain: "WWW.Example.COM.", suffix: "com", want: "example.com",
		},
		"domain equal to suffix": {domain: "com", suffix: "com", want: "com"},
		"empty domain":           {domain: "", suffix: "com", want: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, OrganisationalDomain(tc.domain, tc.suffix))
		})
	}
}

// TestDMARCFullInheritsFromOrganisationalDomain is the correctness fix that
// matters most here: without fallback, every subdomain of a protected domain
// is reported as unprotected, which is a false positive at scale.
func TestDMARCFullInheritsFromOrganisationalDomain(t *testing.T) {
	r := &fakeDMARCResolver{txt: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:d@example.com"},
	}}

	got := ids(DMARCFull(context.Background(), Origin{Target: "mail.example.com"},
		r, nil, "example.com"))

	assert.Contains(t, got, "SURF-DMARC-009")
	assert.NotContains(t, got, "SURF-DMARC-001",
		"an inherited policy means the name is not unprotected")
}

// TestDMARCFullInheritedWeaknessesStillApply guards the opposite error: falling
// back must not launder a weak policy into a clean result.
func TestDMARCFullInheritedWeaknessesStillApply(t *testing.T) {
	r := &fakeDMARCResolver{txt: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=none"},
	}}

	got := ids(DMARCFull(context.Background(), Origin{Target: "mail.example.com"},
		r, nil, "example.com"))

	assert.Contains(t, got, "SURF-DMARC-009")
	assert.Contains(t, got, "SURF-DMARC-002", "the inherited p=none still applies")
	assert.Contains(t, got, "SURF-DMARC-005", "the inherited record still has no rua")
}

func TestDMARCFullNoRecordAnywhere(t *testing.T) {
	r := &fakeDMARCResolver{txt: map[string][]string{}}

	got := ids(DMARCFull(context.Background(), Origin{Target: "mail.example.com"},
		r, nil, "example.com"))

	assert.Equal(t, []string{"SURF-DMARC-001"}, got)
}

func TestDMARCFullOrgDomainItselfIsNotProbed(t *testing.T) {
	r := &fakeDMARCResolver{txt: map[string][]string{}}

	_ = DMARCFull(context.Background(), Origin{Target: "example.com"}, r, nil, "example.com")

	assert.Empty(t, r.queries, "the organisational domain must not look itself up")
}

// TestDMARCFullExternalDestinationUnauthorised is the silent failure the spec
// singles out: the record looks correct and no reports are ever delivered.
func TestDMARCFullExternalDestinationUnauthorised(t *testing.T) {
	r := &fakeDMARCResolver{txt: map[string][]string{}}
	records := []string{"v=DMARC1; p=reject; rua=mailto:reports@thirdparty.example"}

	findings := DMARCFull(context.Background(), Origin{Target: "example.com"},
		r, records, "example.com")

	assert.Contains(t, ids(findings), "SURF-DMARC-006")

	var sawName bool
	for _, f := range findings {
		for _, e := range f.Evidence {
			if e.Name == "dmarc.authorisation_record" &&
				e.Value == "example.com._report._dmarc.thirdparty.example" {
				sawName = true
			}
		}
	}
	assert.True(t, sawName, "the operator needs the exact record name to publish")
}

func TestDMARCFullExternalDestinationAuthorised(t *testing.T) {
	r := &fakeDMARCResolver{txt: map[string][]string{
		"example.com._report._dmarc.thirdparty.example": {"v=DMARC1"},
	}}
	records := []string{"v=DMARC1; p=reject; rua=mailto:reports@thirdparty.example"}

	got := ids(DMARCFull(context.Background(), Origin{Target: "example.com"},
		r, records, "example.com"))

	assert.NotContains(t, got, "SURF-DMARC-006")
}

// TestDMARCFullInternalDestinationNeedsNoAuthorisation avoids a false positive:
// RFC 7489 requires the authorisation record only for external destinations.
func TestDMARCFullInternalDestinationNeedsNoAuthorisation(t *testing.T) {
	r := &fakeDMARCResolver{txt: map[string][]string{}}

	for _, uri := range []string{"mailto:d@example.com", "mailto:d@reports.example.com"} {
		t.Run(uri, func(t *testing.T) {
			records := []string{"v=DMARC1; p=reject; rua=" + uri}
			got := ids(DMARCFull(context.Background(), Origin{Target: "example.com"},
				r, records, "example.com"))
			assert.NotContains(t, got, "SURF-DMARC-006")
		})
	}
}

func TestDMARCFullChecksEachDestinationOnce(t *testing.T) {
	r := &fakeDMARCResolver{txt: map[string][]string{}}
	records := []string{
		"v=DMARC1; p=reject; rua=mailto:a@third.example,mailto:b@third.example; " +
			"ruf=mailto:c@third.example",
	}

	findings := DMARCFull(context.Background(), Origin{Target: "example.com"},
		r, records, "example.com")

	var count int
	for _, f := range findings {
		if f.ID == "SURF-DMARC-006" {
			count++
		}
	}
	require.Equal(t, 1, count, "one destination is one defect, however many addresses use it")
}

func TestReportDestination(t *testing.T) {
	tests := map[string]struct {
		uri  string
		want string
	}{
		"plain mailto":                    {uri: "mailto:d@example.com", want: "example.com"},
		"size limit stripped":             {uri: "mailto:d@example.com!10m", want: "example.com"},
		"case normalised":                 {uri: "MAILTO:D@Example.COM", want: "example.com"},
		"whitespace trimmed":              {uri: "  mailto:d@example.com  ", want: "example.com"},
		"https is not a mail destination": {uri: "https://example.com/report", want: ""},
		"malformed address":               {uri: "mailto:nodomain", want: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, reportDestination(tc.uri))
		})
	}
}

func TestDMARCFullWithoutResolverStillAppliesRecordRules(t *testing.T) {
	got := ids(DMARCFull(context.Background(), Origin{Target: "example.com"},
		nil, []string{"v=DMARC1; p=none"}, "example.com"))

	assert.Contains(t, got, "SURF-DMARC-002")
	assert.NotContains(t, got, "SURF-DMARC-006", "no resolver means no external verification")
}

// failingDMARCResolver fails every lookup with a supplied error, standing in
// for a resolver that cannot answer rather than one that answers "no record".
type failingDMARCResolver struct{ err error }

func (f failingDMARCResolver) TXT(_ context.Context, _ string) ([]string, error) {
	return nil, f.err
}

// A lookup that could not be performed must not be reported as a missing
// record. The two are indistinguishable in the return signature and entirely
// different in meaning: one is a defect in the target's configuration, the
// other is a gap in the assessment. Conflating them sends an operator to
// repair a record that may already be correct — and under a scope guard, which
// refuses every external destination by construction, it would do so on every
// single assessment.
func TestDMARCFullUnansweredLookupIsNotAMissingRecord(t *testing.T) {
	records := []string{"v=DMARC1; p=reject; rua=mailto:reports@thirdparty.example"}

	failures := map[string]error{
		"scope guard refused the egress": fmt.Errorf("refused: %w", vantage.ErrOutOfScope),
		"network withheld by the caller": fmt.Errorf("withheld: %w", vantage.ErrNetworkDisabled),
		"resolver unreachable":           fmt.Errorf("dial: %w", vantage.ErrResolverUnreachable),
		"unclassified transport failure": errors.New("error: i/o timeout"),
	}

	for name, err := range failures {
		t.Run(name, func(t *testing.T) {
			got := ids(DMARCFull(context.Background(), Origin{Target: "example.com"},
				failingDMARCResolver{err: err}, records, "example.com"))

			assert.NotContains(t, got, "SURF-DMARC-006",
				"an unanswered lookup establishes nothing about the destination")
		})
	}
}

// The converse: a definitive absence must still raise. Suppressing the finding
// whenever an error is returned would silence the rule altogether, since a
// resolver reports "no such record" as an error too.
func TestDMARCFullDefiniteAbsenceStillRaises(t *testing.T) {
	records := []string{"v=DMARC1; p=reject; rua=mailto:reports@thirdparty.example"}

	absences := map[string]error{
		"sentinel":              fmt.Errorf("no TXT: %w", vantage.ErrNotFound),
		"unwrapped not found":   errors.New("error: not found"),
		"legacy implementation": errors.New("NXDOMAIN: record Not Found"),
	}

	for name, err := range absences {
		t.Run(name, func(t *testing.T) {
			got := ids(DMARCFull(context.Background(), Origin{Target: "example.com"},
				failingDMARCResolver{err: err}, records, "example.com"))

			assert.Contains(t, got, "SURF-DMARC-006",
				"a definitive absence is a conclusion about the target")
		})
	}
}

// A scope guard whose refusal message happens to contain "not found" must
// still be classified by its sentinel, not by its wording.
func TestDMARCFullSentinelBeatsWording(t *testing.T) {
	records := []string{"v=DMARC1; p=reject; rua=mailto:reports@thirdparty.example"}
	err := fmt.Errorf("host not found in scope: %w", vantage.ErrOutOfScope)

	got := ids(DMARCFull(context.Background(), Origin{Target: "example.com"},
		failingDMARCResolver{err: err}, records, "example.com"))

	assert.NotContains(t, got, "SURF-DMARC-006")
}
