package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/finding"
)

func TestNewAssessorRequiresResolver(t *testing.T) {
	// A nil resolver must be refused at construction rather than discovered
	// mid-run. An assessor that quietly invented its own egress would slip
	// straight past a consumer's scope guard.
	_, err := NewAssessor(nil)
	require.Error(t, err)

	a, err := NewAssessor(testClient)
	require.NoError(t, err)
	assert.NotNil(t, a)
}

// TestCatalogueCoversEveryCheck is the guard that makes a consumer's signal
// registry maintainable. Trawl builds its mapping from this manifest, so a
// check whose findings are missing here would raise identifiers downstream
// that have nowhere to go and would be silently dropped.
func TestCatalogueCoversEveryCheck(t *testing.T) {
	a, err := NewAssessor(testClient, WithVersion("1.2.3"))
	require.NoError(t, err)

	caps, err := a.Catalogue(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "1.2.3", caps.Version)
	assert.Equal(t, finding.SchemaVersion, caps.SchemaVersion)
	assert.Equal(t, GradeVersion, caps.GradeVersion)
	assert.Len(t, caps.Checks, len(Names()),
		"every registered check must appear in the manifest")

	for _, c := range caps.Checks {
		assert.Len(t, c.Catalogue, len(c.Findings),
			"check %q declares findings with no catalogue entry", c.Name)
		for _, e := range c.Catalogue {
			assert.NotEmpty(t, e.ID)
			assert.NotEmpty(t, e.Title, "catalogue entry %q has no title", e.ID)
		}
	}
}

// TestCatalogueResolvesDeepProfileMembership pins that the manifest never
// exposes the nil sentinel used internally to mean "everything". A consumer
// reading an empty membership would conclude the deep profile runs nothing.
func TestCatalogueResolvesDeepProfileMembership(t *testing.T) {
	a, err := NewAssessor(testClient)
	require.NoError(t, err)
	caps, err := a.Catalogue(context.Background())
	require.NoError(t, err)

	byName := map[string]ProfileCapability{}
	for _, p := range caps.Profiles {
		byName[p.Name] = p
	}
	require.Len(t, caps.Profiles, len(Profiles()))

	deep := byName[string(ProfileDeep)]
	assert.Len(t, deep.Checks, len(Names()),
		"the deep profile must enumerate every registered check")
	for _, p := range caps.Profiles {
		assert.NotEmpty(t, p.Checks, "profile %q has no members", p.Name)
		assert.NotEmpty(t, p.Summary, "profile %q has no summary", p.Name)
	}
}

// TestCatalogueDeclaresThirdPartyEgress lets an operator review who the tool
// will talk to besides the targets, before it talks to them.
func TestCatalogueDeclaresThirdPartyEgress(t *testing.T) {
	a, err := NewAssessor(testClient)
	require.NoError(t, err)
	caps, err := a.Catalogue(context.Background())
	require.NoError(t, err)

	assert.NotEmpty(t, caps.ThirdPartyEndpoints)
	assert.Equal(t, ThirdPartyEndpointHosts(), caps.ThirdPartyEndpoints)
}

// TestAssessRejectsUnknownCheck ensures a misspelled selection fails loudly.
// Silently assessing less than asked is the precise failure mode a security
// tool must never have.
func TestAssessRejectsUnknownCheck(t *testing.T) {
	a, err := NewAssessor(testClient)
	require.NoError(t, err)

	_, err = a.Assess(context.Background(), Request{
		Targets:   []string{"example.com"},
		Selection: Selection{Only: []string{"definitely-not-a-check"}},
	})
	require.Error(t, err)
}

// TestAssessStampsProvenance checks that a stored result can later be
// attributed to the code that produced it.
func TestAssessStampsProvenance(t *testing.T) {
	a, err := NewAssessor(testClient, WithVersion("9.9.9"))
	require.NoError(t, err)

	res, err := a.Assess(context.Background(), Request{
		Targets:   []string{"example.com"},
		Selection: Selection{Only: []string{"spf"}, NoNetwork: true},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "vantage", res.Tool.Name)
	assert.Equal(t, "9.9.9", res.Tool.Version)
	assert.NotEmpty(t, res.Resolvers, "a result must record how it was resolved")
}

// TestAssessDoesNotMutateAssessor guards the property that makes an Assessor
// safe to share. Two concurrent requests with different selections must not
// see one another's configuration.
func TestAssessDoesNotMutateAssessor(t *testing.T) {
	a, err := NewAssessor(testClient, WithConcurrency(4, 4))
	require.NoError(t, err)

	base, ok := a.(*Runner)
	require.True(t, ok, "NewAssessor should return a *Runner")
	require.Empty(t, base.Checks)

	_, err = a.Assess(context.Background(), Request{
		Targets:   []string{"example.com"},
		Selection: Selection{Only: []string{"spf"}, NoNetwork: true},
	})
	require.NoError(t, err)

	assert.Empty(t, base.Checks,
		"Assess must not write the request's selection back onto the assessor")
	assert.Nil(t, base.Observer)
	assert.Equal(t, 4, base.Concurrency)
}

// TestRequestConcurrencyOverridesDefault pins that zero means "unset" at the
// request level rather than "no concurrency", which would deadlock or serialise
// a run depending on how it was handled.
func TestRequestConcurrencyOverridesDefault(t *testing.T) {
	assert.Equal(t, 7, pick(7, 3))
	assert.Equal(t, 3, pick(0, 3))
	assert.Equal(t, 0, pick(0, 0))
}
