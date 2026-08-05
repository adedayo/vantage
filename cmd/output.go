package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/report"
)

// Output-related global flag values.
var (
	outputFormat    string
	minSeverity     string
	failOnSeverity  string
	outputFields    []string
	summaryOnly     bool
	noCatalogueText bool
	noColour        bool
	quiet           bool
	showFindings    bool
)

// registerOutputFlags adds the reporting flags to the root command.
func registerOutputFlags(cmd *cobra.Command) {
	f := cmd.PersistentFlags()

	f.StringVarP(&outputFormat, "format", "o", string(report.FormatText),
		fmt.Sprintf("Output format: %s.", joinOr(report.Formats())))
	f.BoolVar(&showFindings, "findings", false,
		"Assess the retrieved records and report security findings, not just the raw record.")
	f.StringVar(&minSeverity, "severity", "info",
		"Only report findings at or above this severity: info, low, medium, high, critical.")
	f.StringVar(&failOnSeverity, "fail-on", "",
		"Exit with status 3 if any finding is at or above this severity. Off by default.")
	f.StringSliceVar(&outputFields, "fields", nil,
		fmt.Sprintf("Restrict structured output to these finding fields (%s). Reduces output size.",
			joinOr(report.FieldNames())))
	f.BoolVar(&summaryOnly, "summary", false,
		"Report counts and check states only, omitting per-finding detail.")
	f.BoolVar(&noCatalogueText, "no-catalogue-text", false,
		"Omit description and remediation prose; resolve it later with 'vantage explain <id>'.")
	f.BoolVar(&noColour, "no-color", false, "Disable coloured output.")
	f.BoolVarP(&quiet, "quiet", "q", false, "Suppress explanatory text.")
}

func joinOr(values []string) string {
	out := ""
	for i, v := range values {
		switch {
		case i == 0:
			out = v
		case i == len(values)-1:
			out += " or " + v
		default:
			out += ", " + v
		}
	}
	return out
}

// reportOptions resolves the output flags into renderer options, validating
// them up front so a bad flag fails immediately with exit code 2 rather than
// after a lengthy assessment.
func reportOptions() (report.Options, error) {
	opts := report.DefaultOptions()

	format, err := report.ParseFormat(outputFormat)
	if err != nil {
		return opts, withExitCode(ExitUsage, err)
	}
	opts.Format = format

	sev, err := finding.ParseSeverity(minSeverity)
	if err != nil {
		return opts, withExitCode(ExitUsage, err)
	}
	opts.MinSeverity = sev

	if err := validateFields(outputFields); err != nil {
		return opts, withExitCode(ExitUsage, err)
	}
	opts.Fields = outputFields
	opts.Summary = summaryOnly
	opts.NoCatalogueText = noCatalogueText
	opts.Quiet = quiet
	opts.Colour = useColour(format)

	return opts, nil
}

func validateFields(fields []string) error {
	valid := map[string]bool{}
	for _, name := range report.FieldNames() {
		valid[name] = true
	}
	for _, f := range fields {
		if !valid[f] {
			return fmt.Errorf("error: unknown field %q (want one of: %s)", f, joinOr(report.FieldNames()))
		}
	}
	return nil
}

// useColour enables colour only for text output on an interactive terminal,
// and honours the NO_COLOR convention. Structured output is never coloured:
// ANSI escapes in a JSON document would be a parsing hazard.
func useColour(format report.Format) bool {
	if noColour || format.Structured() {
		return false
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	return isTerminal(os.Stdout)
}

// isTerminal reports whether f is an interactive terminal. Progress indicators
// and colour are suppressed when it is not, so that redirected output stays
// clean and machine-readable.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// failOn resolves the --fail-on flag.
func failOn() (finding.Severity, bool, error) {
	if failOnSeverity == "" || failOnSeverity == "off" {
		return finding.SeverityInfo, false, nil
	}
	sev, err := finding.ParseSeverity(failOnSeverity)
	if err != nil {
		return finding.SeverityInfo, false, withExitCode(ExitUsage, err)
	}
	return sev, true, nil
}

// newResult starts a result envelope stamped with the running binary's version
// and the resolvers in use, so that output is self-describing and reproducible.
func newResult() *finding.Result {
	v, _, _ := buildInfo()
	result := finding.NewResult("vantage", v)
	if dnsClient != nil {
		result.Resolvers = dnsClient.Servers()
	}
	return result
}

// emit renders the result to stdout and returns the error carrying the process
// exit code.
//
// Rendering always goes to stdout and diagnostics always to stderr, so that
// redirecting stdout yields a valid document regardless of what went wrong.
func emit(result *finding.Result) error {
	opts, err := reportOptions()
	if err != nil {
		return err
	}
	threshold, thresholdSet, err := failOn()
	if err != nil {
		return err
	}

	result.Finalise()
	if err := report.Render(os.Stdout, result, opts); err != nil {
		return withExitCode(ExitError, err)
	}

	if code := resultExitCode(result, threshold, thresholdSet); code != ExitOK {
		return &silentExit{code: code}
	}
	return nil
}

// structuredOutput reports whether the user asked for a machine-readable
// format, which callers use to decide whether to print a bare record or a full
// envelope.
func structuredOutput() bool {
	format, err := report.ParseFormat(outputFormat)
	return err == nil && format.Structured()
}
