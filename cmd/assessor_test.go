package cmd

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/audit"
)

// countingStub records whether anything was asked of the resolver.
type countingStub struct {
	stubResolver
	queries atomic.Int64
}

func (c *countingStub) ExchangeFrom(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error) {
	c.queries.Add(1)
	return c.stubResolver.ExchangeFrom(ctx, name, qtype)
}

// The catalogue is what an operator reads to decide whether to authorise a run
// at all. If describing the tool's capabilities itself required egress, that
// review could not be done before consent was given.
func TestCatalogueListingMakesNoQueries(t *testing.T) {
	stub := &countingStub{}
	assessor, err := audit.NewAssessor(stub)
	require.NoError(t, err)

	require.NoError(t, listChecks(context.Background(), assessor))
	assert.Zero(t, stub.queries.Load(),
		"listing the catalogue must not touch the network")
}

// The CLI now shares the embedding contract, so the catalogue it prints must be
// the same one a consumer would receive. A divergence would make --list-checks
// documentation rather than evidence.
func TestCatalogueDescribesEveryRegisteredCheck(t *testing.T) {
	assessor, err := audit.NewAssessor(stubResolver{})
	require.NoError(t, err)

	caps, err := assessor.Catalogue(context.Background())
	require.NoError(t, err)

	assert.Len(t, caps.Checks, len(audit.Descriptions()),
		"the catalogue omits a registered check")
	assert.NotEmpty(t, caps.Profiles)

	for _, c := range caps.Checks {
		assert.NotEmpty(t, c.Name)
		// A check that declares no egress has not declared it, which is worse
		// than declaring a broad one: the operator would under-estimate the
		// blast radius rather than over-estimate it.
		assert.NotEmpty(t, c.Egress.Describe(), "check %q declares no egress", c.Name)
	}
}

// An assessor cannot be built without egress. Falling back to an ambient
// default would defeat the scope guard an embedding consumer wraps around it,
// silently, at the exact moment it mattered.
func TestAssessorRequiresAResolver(t *testing.T) {
	_, err := audit.NewAssessor(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolver")
}

// Provenance must survive the indirection: results stamped with the library's
// version rather than the binary's would misattribute findings after a
// downstream release.
func TestAssessorStampsTheBuildVersion(t *testing.T) {
	assessor, err := audit.NewAssessor(stubResolver{}, audit.WithVersion("1.2.3-test"))
	require.NoError(t, err)

	caps, err := assessor.Catalogue(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "1.2.3-test", caps.Version)
}
