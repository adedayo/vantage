package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/observation"
)

// TestDMARCTagsSurviveAsData is the reason the email observation exists.
//
// A consumer computing severity needs the policy, the percentage and the
// alignment modes. The alternative is re-parsing the rendered record, which
// means a second parser that can disagree with this one — and when two parsers
// disagree, one half of a system reports a domain as protected while the other
// reports it as exposed, with nothing to say which is right.
func TestDMARCTagsSurviveAsData(t *testing.T) {
	obs := analyse.ParseDMARC(
		"v=DMARC1; p=reject; sp=none; pct=40; aspf=s; adkim=r; rua=mailto:d@example.test",
	).Observation(1)

	assert.Equal(t, observation.PresencePublished, obs.Presence)
	assert.Equal(t, "reject", obs.Policy)
	assert.Equal(t, "none", obs.SubdomainPolicy)
	assert.Equal(t, 40, obs.Percent)
	assert.Equal(t, "s", obs.AlignmentSPF)
	assert.Equal(t, "r", obs.AlignmentDKIM)
	assert.True(t, obs.AggregateReporting)
}

// TestPartialEnforcementIsNotEnforcement.
//
// p=reject at pct=40 instructs receivers to reject 40% of failing mail. A
// reader told only "policy: reject" concludes the spoofing route is closed,
// when it is open three times in five. Enforcing is the judgement, so it is
// made once, here, rather than by every consumer.
func TestPartialEnforcementIsNotEnforcement(t *testing.T) {
	partial := analyse.ParseDMARC("v=DMARC1; p=reject; pct=40").Observation(1)
	assert.False(t, partial.Enforcing(), "a policy applied to part of the mail is partial enforcement")

	full := analyse.ParseDMARC("v=DMARC1; p=reject").Observation(1)
	assert.True(t, full.Enforcing(), "pct defaults to 100, as the RFC specifies")

	monitor := analyse.ParseDMARC("v=DMARC1; p=none").Observation(1)
	assert.False(t, monitor.Enforcing(), "monitoring observes spoofed mail; it does not stop it")
}

// TestAnAbsentDMARCIsAbsentNotUnknown keeps the two negatives apart. The
// resolver answered and there was nothing there — that is a fact about the
// domain, and it must not be confused with a lookup that never completed.
func TestAnAbsentDMARCIsAbsentNotUnknown(t *testing.T) {
	obs := analyse.AbsentDMARC()

	assert.Equal(t, observation.PresenceAbsent, obs.Presence)
	assert.True(t, obs.Presence.Settled(), "an answered question is settled, whichever way it went")
	assert.Equal(t, 100, obs.Percent, "the RFC default applies even with no record, so comparisons hold")
}

// TestProbedAbsenceIsNotConclusive is the DKIM rule the capability spec states
// outright: never record "this domain has no DKIM".
//
// Selectors are not enumerable from DNS. Probing thirteen common ones and
// finding nothing establishes nothing about a domain that signs with a
// tenant-specific selector, and a CISO told "DKIM is missing" would go and
// commission work that is already done.
func TestProbedAbsenceIsNotConclusive(t *testing.T) {
	probed := analyse.DKIMObservation([]string{"default", "google"}, nil, true)

	assert.False(t, probed.Conclusive(),
		"guessing selectors and finding none proves nothing about the domain")
	assert.Equal(t, []string{"default", "google"}, probed.SelectorsExamined,
		"what was tried must be visible, or the reader cannot judge the search")
	assert.Empty(t, probed.SelectorsFound)
}

// TestNamedSelectorsMakeAbsenceConclusive is the other half, and the reason
// the selector list had to become configurable.
//
// An operator who names their selectors is stating a fact about their own
// deployment. Finding nothing under those names is then a real absence, and
// saying so is exactly what they need.
func TestNamedSelectorsMakeAbsenceConclusive(t *testing.T) {
	named := analyse.DKIMObservation([]string{"acme2026"}, nil, false)

	assert.True(t, named.Conclusive(),
		"selectors the operator named are evidence; their absence is an answer")
}

// TestUsableKeysMatchTheFindingRule. The count and the findings must be
// derived from one definition, or a domain reads as signing correctly in one
// place and as revoked in another.
func TestUsableKeysMatchTheFindingRule(t *testing.T) {
	keys := []analyse.DKIMKey{
		{Selector: "live", Valid: true},
		{Selector: "old", Valid: true, Revoked: true},
		{Selector: "broken", Valid: false},
	}

	obs := analyse.DKIMObservation([]string{"live", "old", "broken"}, keys, true)

	assert.Equal(t, 1, obs.UsableKeys, "a revoked or unparseable key is not a working signature")
	assert.Equal(t, []string{"live", "old", "broken"}, obs.SelectorsFound,
		"every selector that answered is recorded, usable or not")
	assert.True(t, obs.Conclusive(), "a key was found, so the search settled the question")
}

// TestAdjacentRecordsShareAShape. A consumer tiers these as a group; one that
// had to recognise each by name would silently fail to tier a record added
// later, and the new one would arrive at whatever severity the default gives.
func TestAdjacentRecordsShareAShape(t *testing.T) {
	present := analyse.AdjacentObservation("MTASTS", true, "testing")
	assert.Equal(t, "mtasts", present.Kind, "the kind is normalised so consumers can switch on it")
	assert.Equal(t, observation.PresencePublished, present.Presence)
	assert.Equal(t, "testing", present.Detail)

	absent := analyse.AdjacentObservation("bimi", false, "")
	assert.Equal(t, observation.PresenceAbsent, absent.Presence)
}

// TestSPFObservationCarriesTheAllMechanism.
//
// "+all" authorises the entire internet to send as the domain — worse than
// publishing nothing, because it converts a receiver check that would have
// been inconclusive into one that passes. A consumer must be able to see it
// without parsing the record itself.
func TestSPFObservationCarriesTheAllMechanism(t *testing.T) {
	findings, obs := analyse.SPFObserved(t.Context(),
		analyse.Origin{Target: "example.test"}, nil,
		[]string{"v=spf1 include:_spf.example.net +all"}, true)

	assert.Equal(t, observation.PresencePublished, obs.Presence)
	assert.Equal(t, "+", obs.AllMechanism)
	assert.True(t, obs.Valid)
	assert.True(t, obs.SendsMail)
	require.NotEmpty(t, findings, "a permissive all-mechanism is also a finding")
}

// TestSPFObservationAndFindingsComeFromOneEvaluation. The observation must not
// cost a second walk of the include graph: an assessment that doubles its own
// query count on upgrade is one an operator's egress policy may start refusing.
func TestSPFObservationAndFindingsComeFromOneEvaluation(t *testing.T) {
	counter := &countingSPFResolver{}

	_, obs := analyse.SPFObserved(t.Context(),
		analyse.Origin{Target: "example.test"}, counter,
		[]string{"v=spf1 include:a.example.test -all"}, true)

	assert.Equal(t, "-", obs.AllMechanism)
	assert.Equal(t, 1, obs.Lookups, "the include is one DNS-querying mechanism")
	assert.LessOrEqual(t, counter.calls, 1,
		"the observation reuses the evaluation rather than repeating it")
}

type countingSPFResolver struct{ calls int }

func (c *countingSPFResolver) TXT(_ context.Context, _ string) ([]string, error) {
	c.calls++
	return nil, nil
}

func (c *countingSPFResolver) HasRecords(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
