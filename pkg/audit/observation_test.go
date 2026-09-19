package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/observation"
)

// The structured observation has to survive the journey from the check to the
// result. Everything else in spec 015 rests on this: a consumer reads the
// result, not the outcome.
func TestObservationReachesTheResult(t *testing.T) {
	withRegistry(t)

	net := &observation.Network{
		Domain:        "example.test",
		FailedSources: []string{"gcp"},
	}
	check := stub("net", NetworkDNS, Outcome{
		State:       finding.StateOK,
		Records:     []string{"provenance: aws ranges from https://example.test fetched 2026-09-19"},
		Observation: &finding.Observation{Network: net},
	}, nil)

	res := finding.NewResult("vantage", "test")
	r := &Runner{Resolver: testClient, Checks: []Check{check}, Concurrency: 1}
	require.NoError(t, r.Run(context.Background(), res, "example.test"))

	require.Len(t, res.Checks, 1)
	got := res.Checks[0].Observation
	require.NotNil(t, got, "the structured observation must travel with the result")
	require.NotNil(t, got.Network)
	assert.Equal(t, "example.test", got.Network.Domain)

	// A source that failed to load must remain visible. Without it an
	// unattributed address is indistinguishable from an address known to be in
	// no provider range, which is a coverage gap reading as a clean result.
	assert.Equal(t, []string{"gcp"}, got.Network.FailedSources)

	// Additive, not a replacement: the rendered records are untouched.
	assert.Len(t, res.Checks[0].Records, 1)
}

// A check that gathers no structured observation must contribute none, so that
// "nothing to report" stays distinguishable from "this check does not gather
// facts of that kind".
func TestAbsentObservationStaysAbsent(t *testing.T) {
	withRegistry(t)

	check := stub("spf", NetworkDNS, Outcome{
		State: finding.StateOK, Records: []string{"v=spf1 -all"},
	}, nil)

	res := finding.NewResult("vantage", "test")
	r := &Runner{Resolver: testClient, Checks: []Check{check}, Concurrency: 1}
	require.NoError(t, r.Run(context.Background(), res, "example.test"))

	require.Len(t, res.Checks, 1)
	assert.Nil(t, res.Checks[0].Observation)
}

// A check that fails part-way may still have gathered something, and what it
// gathered is often the justification for the failure. The records are already
// kept in that case; the observation is kept for the same reason.
func TestObservationSurvivesAFailedCheck(t *testing.T) {
	withRegistry(t)

	ct := &observation.CT{Domain: "example.test", Discovered: 3}
	check := stub("ct", NetworkHTTPS, Outcome{
		Records:     []string{"warning: log service rate-limited"},
		Observation: &finding.Observation{CT: ct},
	}, errors.New("rate limited"))

	res := finding.NewResult("vantage", "test")
	r := &Runner{Resolver: testClient, Checks: []Check{check}, Concurrency: 1}
	require.NoError(t, r.Run(context.Background(), res, "example.test"))

	require.Len(t, res.Checks, 1)
	assert.Equal(t, finding.StateCheckFailed, res.Checks[0].State)
	require.NotNil(t, res.Checks[0].Observation)
	require.NotNil(t, res.Checks[0].Observation.CT)
	assert.Equal(t, 3, res.Checks[0].Observation.CT.Discovered)
}
