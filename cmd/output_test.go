package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/report"
)

// resetOutputFlags restores the package-level flag values between tests, since
// cobra binds them globally.
func resetOutputFlags(t *testing.T) {
	t.Helper()
	prev := struct {
		format, severity, failOn string
		fields                   []string
		summary, noText, noColor bool
		quiet, findings          bool
	}{
		outputFormat, minSeverity, failOnSeverity, outputFields,
		summaryOnly, noCatalogueText, noColour, quiet, showFindings,
	}
	t.Cleanup(func() {
		outputFormat, minSeverity, failOnSeverity, outputFields = prev.format, prev.severity, prev.failOn, prev.fields
		summaryOnly, noCatalogueText, noColour = prev.summary, prev.noText, prev.noColor
		quiet, showFindings = prev.quiet, prev.findings
	})

	outputFormat = string(report.FormatText)
	minSeverity = "info"
	failOnSeverity = ""
	outputFields = nil
	summaryOnly, noCatalogueText, noColour, quiet, showFindings = false, false, false, false, false
}

func TestReportOptionsDefaults(t *testing.T) {
	resetOutputFlags(t)

	opts, err := reportOptions()
	require.NoError(t, err)
	assert.Equal(t, report.FormatText, opts.Format)
	assert.Equal(t, finding.SeverityInfo, opts.MinSeverity)
}

func TestReportOptionsRejectsBadFormat(t *testing.T) {
	resetOutputFlags(t)
	outputFormat = "yaml"

	_, err := reportOptions()
	require.Error(t, err)
	assert.Equal(t, ExitUsage, exitCodeOf(err),
		"a bad flag must exit 2, not 1")
}

func TestReportOptionsRejectsBadSeverity(t *testing.T) {
	resetOutputFlags(t)
	minSeverity = "catastrophic"

	_, err := reportOptions()
	require.Error(t, err)
	assert.Equal(t, ExitUsage, exitCodeOf(err))
}

func TestReportOptionsRejectsUnknownField(t *testing.T) {
	resetOutputFlags(t)
	outputFields = []string{"severity", "nonsense"}

	_, err := reportOptions()
	require.Error(t, err)
	assert.Equal(t, ExitUsage, exitCodeOf(err))
	assert.Contains(t, err.Error(), "nonsense")
}

func TestReportOptionsAcceptsKnownFields(t *testing.T) {
	resetOutputFlags(t)
	outputFields = report.FieldNames()

	_, err := reportOptions()
	assert.NoError(t, err)
}

// TestStructuredOutputNeverColoured guards against ANSI escapes leaking into a
// JSON document, which would make it unparseable.
func TestStructuredOutputNeverColoured(t *testing.T) {
	resetOutputFlags(t)
	outputFormat = string(report.FormatJSON)

	opts, err := reportOptions()
	require.NoError(t, err)
	assert.False(t, opts.Colour)
}

func TestFailOnDefaultsToOff(t *testing.T) {
	resetOutputFlags(t)

	_, set, err := failOn()
	require.NoError(t, err)
	assert.False(t, set, "--fail-on must be off unless requested")
}

func TestFailOnParsing(t *testing.T) {
	resetOutputFlags(t)
	failOnSeverity = "high"

	sev, set, err := failOn()
	require.NoError(t, err)
	assert.True(t, set)
	assert.Equal(t, finding.SeverityHigh, sev)
}

func TestFailOnExplicitOff(t *testing.T) {
	resetOutputFlags(t)
	failOnSeverity = "off"

	_, set, err := failOn()
	require.NoError(t, err)
	assert.False(t, set)
}

func TestFailOnRejectsBadValue(t *testing.T) {
	resetOutputFlags(t)
	failOnSeverity = "very-bad"

	_, _, err := failOn()
	require.Error(t, err)
	assert.Equal(t, ExitUsage, exitCodeOf(err))
}

func TestStructuredOutput(t *testing.T) {
	resetOutputFlags(t)
	assert.False(t, structuredOutput())

	outputFormat = string(report.FormatNDJSON)
	assert.True(t, structuredOutput())
}

func TestJoinOr(t *testing.T) {
	assert.Equal(t, "a", joinOr([]string{"a"}))
	assert.Equal(t, "a or b", joinOr([]string{"a", "b"}))
	assert.Equal(t, "a, b or c", joinOr([]string{"a", "b", "c"}))
}

func TestNewResultCarriesToolMetadata(t *testing.T) {
	prev := dnsClient
	t.Cleanup(func() { dnsClient = prev })
	dnsClient = vantage.NewClient(vantage.Config{Servers: []string{"9.9.9.9:53"}})

	result := newResult()
	assert.Equal(t, "vantage", result.Tool.Name)
	assert.Equal(t, finding.SchemaVersion, result.SchemaVersion)
	assert.NotEmpty(t, result.Resolvers, "output must record which resolvers were used")
}
