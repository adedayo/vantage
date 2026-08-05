package vantage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rename changed the resolver environment variable. An unnoticed change of
// resolver alters results without erroring, so the old name stays honoured.

func TestLegacyResolverEnvVarIsHonoured(t *testing.T) {
	t.Setenv(ResolverEnvVar, "")
	t.Setenv(LegacyResolverEnvVar, "192.0.2.10")
	assert.Contains(t, NewClient(Config{}).Servers(), "192.0.2.10:53")
}

func TestCanonicalResolverEnvVarWinsOverLegacy(t *testing.T) {
	// A host exporting both mid-migration must behave predictably.
	t.Setenv(ResolverEnvVar, "192.0.2.20")
	t.Setenv(LegacyResolverEnvVar, "192.0.2.10")
	got := NewClient(Config{}).Servers()
	require.NotEmpty(t, got)
	assert.Contains(t, got, "192.0.2.20:53")
	assert.NotContains(t, got, "192.0.2.10:53")
}
