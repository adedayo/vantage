package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// ANSI colour codes, applied only when the caller asks for colour (which the
// CLI does only for an interactive terminal).
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
)

// Text layout. The total width is kept within 80 columns so that reports stay
// readable in a default terminal and in pasted incident tickets, rather than
// relying on the terminal to re-wrap them into a ragged mess.
const (
	textWidth    = 80
	detailIndent = "          " // aligns continuation lines under the title
)

func severityColour(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return ansiRed
	case finding.SeverityMedium:
		return ansiYellow
	case finding.SeverityLow:
		return ansiBlue
	default:
		return ansiCyan
	}
}

// renderText writes the analyst-facing report: most severe first, with the
// evidence that justifies each finding and the action that resolves it.
func renderText(w io.Writer, result *finding.Result, opts Options) error {
	paint := func(colour, text string) string {
		if !opts.Colour {
			return text
		}
		return colour + text + ansiReset
	}

	for _, target := range result.Targets {
		fmt.Fprintf(w, "%s  \u2500\u2500 %s\n",
			paint(ansiBold, target), targetSummary(result, target).Describe())
	}
	if len(result.Targets) > 1 {
		// The overall line is separate because the grade applies to the run as
		// a whole; attaching it to each target would imply a per-target grade
		// that has not been calculated.
		fmt.Fprintf(w, "%s  \u2500\u2500 %s\n",
			paint(ansiBold, "overall"), result.Summary.Describe())
	}
	if len(result.Targets) == 0 {
		fmt.Fprintf(w, "%s\n", result.Summary.Describe())
	}

	if opts.Summary {
		return renderPosture(w, result, opts)
	}

	if len(result.Findings) > 0 {
		fmt.Fprintln(w)
	}
	for _, f := range result.Findings {
		label := strings.ToUpper(f.Severity.String())
		suffix := ""
		if f.Suppressed {
			suffix = paint(ansiDim, "  [suppressed: "+f.SuppressionReason+"]")
		}
		fmt.Fprintf(w, "%-9s %s  %s%s\n",
			paint(severityColour(f.Severity), label), paint(ansiBold, f.ID), f.Title, suffix)

		if len(result.Targets) > 1 {
			fmt.Fprintf(w, "          Target: %s\n", f.Target)
		}
		if f.Description != "" && !opts.Quiet {
			fmt.Fprintf(w, "%s%s\n", detailIndent, wrap(f.Description, textWidth-len(detailIndent), detailIndent))
		}
		for _, e := range f.Evidence {
			fmt.Fprintf(w, "%s%s %s\n", detailIndent, paint(ansiDim, "Evidence:"), evidenceLine(e))
		}
		// Rendered after the evidence and labelled distinctly, because it
		// qualifies what the evidence supports rather than adding to it.
		if f.Basis != "" && !opts.Quiet {
			const basisLabel = "Basis: "
			fmt.Fprintf(w, "%s%s%s\n", detailIndent, paint(ansiDim, basisLabel),
				wrap(f.Basis, textWidth-len(detailIndent)-len(basisLabel), detailIndent))
		}
		if f.Remediation != "" && !opts.Quiet {
			const fixLabel = "Fix: "
			fmt.Fprintf(w, "%s%s%s\n", detailIndent, paint(ansiDim, fixLabel),
				wrap(f.Remediation, textWidth-len(detailIndent)-len(fixLabel), detailIndent))
		}
		if f.Confidence < finding.ConfidenceHigh {
			fmt.Fprintf(w, "          %s\n",
				paint(ansiDim, "Confidence: "+f.Confidence.String()+" \u2014 based on inference, verify before acting"))
		}
		fmt.Fprintln(w)
	}

	if err := renderPosture(w, result, opts); err != nil {
		return err
	}

	if len(result.Errors) > 0 {
		fmt.Fprintf(w, "\n%s\n", paint(ansiYellow, "Checks that could not complete:"))
		for _, e := range result.Errors {
			retry := ""
			if e.Retryable {
				retry = " (retryable)"
			}
			fmt.Fprintf(w, "  %-14s %s [%s]%s\n", e.Check, e.Message, e.Code, retry)
		}
	}
	return nil
}

// targetSummary counts the findings belonging to one target.
//
// With a single target this is the whole result, grade included. With several,
// each target gets its own counts but no grade: grading is a run-level policy
// decision and inventing a per-target one here would misrepresent it.
func targetSummary(result *finding.Result, target string) finding.Summary {
	if len(result.Targets) <= 1 {
		return result.Summary
	}
	var s finding.Summary
	for _, f := range result.Findings {
		if f.Target != target {
			continue
		}
		if f.Suppressed {
			s.Suppressed++
			continue
		}
		switch f.Severity {
		case finding.SeverityCritical:
			s.Critical++
		case finding.SeverityHigh:
			s.High++
		case finding.SeverityMedium:
			s.Medium++
		case finding.SeverityLow:
			s.Low++
		case finding.SeverityInfo:
			s.Info++
		}
		s.Total++
	}
	return s
}

// renderPosture prints the at-a-glance state of each check. It deliberately
// distinguishes "not found" from "not checked": conflating them would let a
// reader conclude a control is absent when in truth it was never assessed.
func renderPosture(w io.Writer, result *finding.Result, opts Options) error {
	if len(result.Checks) == 0 {
		return nil
	}
	mark := func(state finding.State) string {
		switch state {
		case finding.StateOK:
			return "\u2713"
		case finding.StateNotFound:
			return "\u2717"
		case finding.StateCheckFailed:
			return "!"
		case finding.StateNotChecked:
			return "\u2013"
		}
		return "?"
	}

	// Group by target so that a bulk run stays readable; a single flat list
	// would leave the reader unable to tell whose control was missing.
	byTarget := map[string][]string{}
	var order []string
	for _, c := range result.Checks {
		if _, seen := byTarget[c.Target]; !seen {
			order = append(order, c.Target)
		}
		byTarget[c.Target] = append(byTarget[c.Target],
			fmt.Sprintf("%s %s", c.Check, mark(c.State)))
	}

	if len(order) == 1 {
		fmt.Fprintf(w, "Posture: %s\n", strings.Join(byTarget[order[0]], "  "))
	} else {
		fmt.Fprintln(w, "Posture:")
		for _, target := range order {
			fmt.Fprintf(w, "  %-24s %s\n", target, strings.Join(byTarget[target], "  "))
		}
	}
	if !opts.Quiet {
		fmt.Fprintf(w, "         %s\n",
			"\u2713 present   \u2717 not found   ! check failed   \u2013 not checked")
	}
	return renderWarnings(w, result)
}

// renderWarnings surfaces records a check marked as warnings.
//
// A check can succeed and still have been unable to do its whole job — the
// provider ranges for one cloud may be unreachable while the rest load. That
// degradation is visible in structured output, but text is the default and the
// most common invocation, and "no findings (grade A)" printed over a check that
// silently lost half its coverage is the most misleading thing this tool could
// say.
func renderWarnings(w io.Writer, result *finding.Result) error {
	var warnings []string
	seen := map[string]bool{}
	for _, c := range result.Checks {
		for _, r := range c.Records {
			if !strings.HasPrefix(r, finding.RecordPrefixWarning) || seen[r] {
				continue
			}
			seen[r] = true
			warnings = append(warnings,
				strings.TrimSpace(strings.TrimPrefix(r, finding.RecordPrefixWarning)))
		}
	}
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(w, "Warning: %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func evidenceLine(e finding.Evidence) string {
	switch {
	case e.Type != "" && e.Name != "":
		return fmt.Sprintf("%s %s = %s", e.Name, e.Type, e.Value)
	case e.Name != "":
		return fmt.Sprintf("%s = %s", e.Name, e.Value)
	default:
		return e.Value
	}
}

// wrap breaks text at width, indenting continuation lines.
func wrap(text string, width int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = word
			continue
		}
		line += " " + word
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n"+indent)
}

// renderJSON writes the complete envelope.
func renderJSON(w io.Writer, result *finding.Result, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if opts.Summary {
		return enc.Encode(summaryEnvelopeOf(result))
	}
	return enc.Encode(result)
}

// summaryEnvelope is the minimal shape emitted by --summary: enough for an
// agent to triage a portfolio cheaply and decide where to look closer.
type summaryEnvelope struct {
	SchemaVersion string            `json:"schema_version"`
	Tool          finding.ToolInfo  `json:"tool"`
	Targets       []string          `json:"targets"`
	Summary       finding.Summary   `json:"summary"`
	FindingIDs    []string          `json:"finding_ids"`
	States        map[string]string `json:"states,omitempty"`
	ErrorCount    int               `json:"error_count"`
}

func summaryEnvelopeOf(result *finding.Result) summaryEnvelope {
	ids := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		if !f.Suppressed {
			ids = append(ids, f.ID)
		}
	}
	states := map[string]string{}
	for _, c := range result.Checks {
		states[c.Check] = string(c.State)
	}
	return summaryEnvelope{
		SchemaVersion: result.SchemaVersion,
		Tool:          result.Tool,
		Targets:       result.Targets,
		Summary:       result.Summary,
		FindingIDs:    ids,
		States:        states,
		ErrorCount:    len(result.Errors),
	}
}

// renderNDJSON streams one JSON object per line: a leading meta record, then
// one record per finding, then one per error. This lets a consumer process
// incrementally and stop early, and keeps memory bounded for bulk runs.
func renderNDJSON(w io.Writer, result *finding.Result, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	meta := map[string]any{
		"kind":           "meta",
		"schema_version": result.SchemaVersion,
		"tool":           result.Tool,
		"started_at":     result.StartedAt,
		"finished_at":    result.FinishedAt,
		"targets":        result.Targets,
		"resolvers":      result.Resolvers,
		"summary":        result.Summary,
	}
	if err := enc.Encode(meta); err != nil {
		return err
	}
	if opts.Summary {
		return nil
	}

	for _, f := range result.Findings {
		if err := enc.Encode(struct {
			Kind string `json:"kind"`
			finding.Finding
		}{Kind: "finding", Finding: f}); err != nil {
			return err
		}
	}
	for _, c := range result.Checks {
		if err := enc.Encode(struct {
			Kind string `json:"kind"`
			finding.CheckResult
		}{Kind: "check", CheckResult: c}); err != nil {
			return err
		}
	}
	for _, e := range result.Errors {
		if err := enc.Encode(struct {
			Kind string `json:"kind"`
			finding.CheckError
		}{Kind: "error", CheckError: e}); err != nil {
			return err
		}
	}
	return nil
}

// csvHeader is the fixed column order for CSV output.
var csvHeader = []string{
	"target", "id", "severity", "confidence", "check", "title",
	"description", "evidence", "remediation", "references", "tags", "suppressed",
}

func renderCSV(w io.Writer, result *finding.Result, _ Options) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, f := range result.Findings {
		evidence := make([]string, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			evidence = append(evidence, evidenceLine(e))
		}
		row := []string{
			f.Target, f.ID, f.Severity.String(), f.Confidence.String(), f.Check, f.Title,
			f.Description, strings.Join(evidence, "; "), f.Remediation,
			strings.Join(f.References, " "), strings.Join(f.Tags, " "),
			strconv.FormatBool(f.Suppressed),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
