package cmd

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/audit"
)

// resetAuditFlags restores the package-level flag state, since cobra flags are
// global and tests must not leak into one another.
func resetAuditFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		auditDomainsFile, auditStdin, auditMaxTargets = "", false, 0
	})
	auditDomainsFile, auditStdin, auditMaxTargets = "", false, 0
}

func TestReadTargetLines(t *testing.T) {
	input := strings.Join([]string{
		"# a comment",
		"",
		"   ",
		"example.com",
		"  spaced.example  ",
		"inline.example # trailing comment",
		"tabbed.example\tignored",
		"#another.example",
	}, "\n")

	got, err := readTargetLines(bufio.NewScanner(strings.NewReader(input)))
	require.NoError(t, err)
	// Comments and stray whitespace are a fact of life in asset inventories;
	// silently mis-parsing them would audit the wrong thing.
	assert.Equal(t, []string{
		"example.com", "spaced.example", "inline.example", "tabbed.example",
	}, got)
}

func TestCollectTargetsFromArgs(t *testing.T) {
	resetAuditFlags(t)
	got, err := collectTargets([]string{"example.com", "example.org"})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com", "example.org"}, got)
}

func TestCollectTargetsFromFile(t *testing.T) {
	resetAuditFlags(t)
	path := filepath.Join(t.TempDir(), "domains.txt")
	require.NoError(t, os.WriteFile(path,
		[]byte("# inventory\nfile-one.example\nfile-two.example\n"), 0o600))

	auditDomainsFile = path
	got, err := collectTargets([]string{"arg.example"})
	require.NoError(t, err)
	assert.Equal(t, []string{"arg.example", "file-one.example", "file-two.example"}, got)
}

func TestCollectTargetsMissingFileIsUsageError(t *testing.T) {
	resetAuditFlags(t)
	auditDomainsFile = filepath.Join(t.TempDir(), "absent.txt")
	_, err := collectTargets(nil)
	require.Error(t, err)
	assert.Equal(t, ExitUsage, exitCodeOf(err))
}

func TestCollectTargetsRequiresInput(t *testing.T) {
	resetAuditFlags(t)
	_, err := collectTargets(nil)
	require.Error(t, err)
	assert.Equal(t, ExitUsage, exitCodeOf(err))
	// The message must name every way of supplying targets, so a caller that
	// got it wrong can correct itself without consulting the manual.
	assert.Contains(t, err.Error(), "--domains-file")
	assert.Contains(t, err.Error(), "--stdin")
}

func TestCollectTargetsEnforcesMaxTargets(t *testing.T) {
	resetAuditFlags(t)
	auditMaxTargets = 2
	_, err := collectTargets([]string{"a.example", "b.example", "c.example"})
	require.Error(t, err)
	assert.Equal(t, ExitUsage, exitCodeOf(err))
	assert.Contains(t, err.Error(), "max-targets")

	// At the limit the run must proceed: the cap is a ceiling, not a fence.
	got, err := collectTargets([]string{"a.example", "b.example"})
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestListChecksSucceeds(t *testing.T) {
	// A catalogue listing must not require egress: an operator reviewing what
	// the tool would do, before authorising it to do anything, is precisely
	// the case where no packet should leave.
	assessor, err := audit.NewAssessor(stubResolver{})
	require.NoError(t, err)
	require.NoError(t, listChecks(context.Background(), assessor))
}

// stubResolver satisfies the resolver contract without reaching the network.
// NewAssessor requires one because there is no safe default; the catalogue
// path never calls it.
type stubResolver struct{}

func (stubResolver) ExchangeFrom(context.Context, string, uint16) (*dns.Msg, string, error) {
	return nil, "", errors.New("error: no egress in tests")
}

func (stubResolver) ExchangeRawFrom(context.Context, string, uint16) (*dns.Msg, string, error) {
	return nil, "", errors.New("error: no egress in tests")
}

func (stubResolver) ExchangeDNSSECRawFrom(context.Context, string, uint16) (*dns.Msg, string, error) {
	return nil, "", errors.New("error: no egress in tests")
}

func (stubResolver) ExchangeWithServer(context.Context, string, string, uint16) (*dns.Msg, error) {
	return nil, errors.New("error: no egress in tests")
}

func (stubResolver) ExchangeDNSSECWithServer(context.Context, string, string, uint16) (*dns.Msg, error) {
	return nil, errors.New("error: no egress in tests")
}

func (stubResolver) Servers() []string { return []string{"stub"} }
