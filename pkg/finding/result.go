package finding

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/adedayo/vantage/pkg/observation"
)

// SchemaVersion identifies the shape of the result envelope. It follows semver:
// additive changes bump the minor component, breaking changes the major.
//
// Once released this is a public contract — agents and SIEM pipelines key on it
// — so it deserves the same care as the library API.
const SchemaVersion = "1.1"

// State distinguishes the three outcomes that a naive report would conflate.
//
// This distinction is the difference between honest and misleading output. "No
// DKIM record found" and "DKIM was never checked" are entirely different
// statements, and a consumer acting on the first when the second is true will
// reach a false conclusion.
type State string

const (
	// StateOK means the check ran and the record or property was present.
	StateOK State = "ok"
	// StateNotFound means the check ran and the record was definitively absent.
	StateNotFound State = "not_found"
	// StateNotChecked means the check did not run — filtered out by profile,
	// skipped for want of a required input, or disabled by a flag.
	StateNotChecked State = "not_checked"
	// StateCheckFailed means the check ran but could not reach a conclusion,
	// typically because of a resolver or network failure.
	StateCheckFailed State = "check_failed"
)

// ErrorCode is a stable, enumerated identifier for a failure class. Consumers
// branch on the code; the accompanying message is free text and must never be
// parsed.
type ErrorCode string

// Error codes. New codes may be added; existing codes never change meaning.
const (
	ErrCodeResolverUnreachable ErrorCode = "RESOLVER_UNREACHABLE"
	ErrCodeTimeout             ErrorCode = "TIMEOUT"
	ErrCodeNotFound            ErrorCode = "NOT_FOUND"
	ErrCodeInvalidRecord       ErrorCode = "INVALID_RECORD"
	ErrCodeNetworkDisabled     ErrorCode = "NETWORK_DISABLED"
	ErrCodeOutOfScope          ErrorCode = "OUT_OF_SCOPE"
	ErrCodeUsage               ErrorCode = "USAGE"
	ErrCodeInternal            ErrorCode = "INTERNAL"
)

// CheckError reports a check that could not complete. It carries a retry hint
// so that an automated consumer does not have to infer retryability from the
// wording of a message.
type CheckError struct {
	Check             string    `json:"check"`
	Target            string    `json:"target,omitempty"`
	Code              ErrorCode `json:"code"`
	Message           string    `json:"message"`
	Retryable         bool      `json:"retryable"`
	RetryAfterSeconds int       `json:"retry_after_seconds,omitempty"`
}

// CheckResult records the outcome of one check against one target, including
// the raw record data so that no information is lost relative to the plain
// record-retrieval commands.
type CheckResult struct {
	Check   string   `json:"check"`
	Target  string   `json:"target"`
	State   State    `json:"state"`
	Records []string `json:"records,omitempty"`
	// Observation is the structured data the check gathered, when it gathers
	// any. Records render the same facts for a reader; this is the contract a
	// consumer reads.
	//
	// A pointer so that "no observation" and "an empty observation" stay
	// distinguishable — in the Go value and, because it is omitted when nil,
	// in the JSON too. A consumer must be able to tell a check that gathered
	// nothing from one that does not gather this kind of fact at all.
	Observation *Observation `json:"observation,omitempty"`
}

// Observation carries the structured facts a check gathered.
//
// One field per kind of observation, each a pointer and each omitted when
// absent. A new kind is added by adding a field: existing consumers are
// unaffected, and none has to interpret an untyped payload to discover what it
// received.
type Observation struct {
	// Network is address attribution: provider, region, jurisdiction, and the
	// provenance of the data that produced them.
	Network *observation.Network `json:"network,omitempty"`
	// CT is what Certificate Transparency disclosed, including names that no
	// longer resolve.
	CT *observation.CT `json:"ct,omitempty"`
}

// Record prefixes marking a line as describing the run rather than the domain.
//
// Most records are observations about the target and are stable between runs
// unless the domain changes. A few describe how the run itself went — a
// provider range file that was unreachable, the age of the data an attribution
// was drawn from — and those vary with network conditions and cache state.
//
// Spec 013 diffs records between runs to detect drift and requires that false
// drift be avoidable, since it destroys trust in the signal faster than missing
// drift does. Marking these lines lets a differ exclude them without having to
// pattern-match prose that may later be reworded.
const (
	// RecordPrefixWarning marks a degradation: something could not be done.
	RecordPrefixWarning = "warning:"
	// RecordPrefixProvenance marks a statement of where data came from and
	// when, which changes whenever the data is refreshed.
	RecordPrefixProvenance = "provenance:"
)

// IsDiagnosticRecord reports whether a record describes the run rather than the
// domain, and so should not be compared when detecting drift.
func IsDiagnosticRecord(record string) bool {
	return strings.HasPrefix(record, RecordPrefixWarning) ||
		strings.HasPrefix(record, RecordPrefixProvenance)
}

// ObservedRecords returns only the records describing the target, in order.
func (c CheckResult) ObservedRecords() []string {
	observed := make([]string, 0, len(c.Records))
	for _, r := range c.Records {
		if !IsDiagnosticRecord(r) {
			observed = append(observed, r)
		}
	}
	return observed
}

// ToolInfo identifies the producing binary.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Summary counts findings by severity and carries the optional posture grade.
type Summary struct {
	Critical   int    `json:"critical"`
	High       int    `json:"high"`
	Medium     int    `json:"medium"`
	Low        int    `json:"low"`
	Info       int    `json:"info"`
	Total      int    `json:"total"`
	Suppressed int    `json:"suppressed"`
	Grade      string `json:"grade,omitempty"`
	// GradeVersion identifies the algorithm that produced Grade. A grade whose
	// meaning can change silently between releases makes trend comparison
	// worthless, so consumers need to know which version they are reading.
	GradeVersion string `json:"grade_version,omitempty"`
}

// Result is the envelope emitted by every structured renderer. It is always
// complete and self-contained: renderers never emit partial fragments.
type Result struct {
	SchemaVersion string        `json:"schema_version"`
	Tool          ToolInfo      `json:"tool"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Resolvers     []string      `json:"resolvers,omitempty"`
	Targets       []string      `json:"targets"`
	Summary       Summary       `json:"summary"`
	Findings      []Finding     `json:"findings"`
	Checks        []CheckResult `json:"checks,omitempty"`
	Errors        []CheckError  `json:"errors,omitempty"`
}

// NewResult starts an empty result with the schema version and start time set.
func NewResult(toolName, toolVersion string) *Result {
	return &Result{
		SchemaVersion: SchemaVersion,
		Tool:          ToolInfo{Name: toolName, Version: toolVersion},
		StartedAt:     time.Now().UTC(),
		Findings:      []Finding{},
		Targets:       []string{},
	}
}

// AddTarget records an assessed target, ignoring duplicates.
func (r *Result) AddTarget(target string) {
	for _, t := range r.Targets {
		if t == target {
			return
		}
	}
	r.Targets = append(r.Targets, target)
}

// Add appends findings to the result.
func (r *Result) Add(findings ...Finding) {
	r.Findings = append(r.Findings, findings...)
}

// AddCheck records the outcome of a check, including its raw records.
func (r *Result) AddCheck(check, target string, state State, records ...string) {
	r.Checks = append(r.Checks, CheckResult{
		Check: check, Target: target, State: state, Records: records,
	})
}

// AddError records a non-fatal check failure. One failed check never suppresses
// the others.
func (r *Result) AddError(e CheckError) {
	r.Errors = append(r.Errors, e)
}

// Finalise sorts the findings deterministically, recomputes the summary and
// stamps the finish time. It must be called before rendering.
//
// Deterministic ordering is not cosmetic: it is what allows two runs against an
// unchanged domain to produce byte-identical output, which in turn is what
// makes caching and the drift detection of spec 013 possible.
func (r *Result) Finalise() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity // most severe first
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.ID < b.ID
	})
	sort.SliceStable(r.Checks, func(i, j int) bool {
		if r.Checks[i].Target != r.Checks[j].Target {
			return r.Checks[i].Target < r.Checks[j].Target
		}
		return r.Checks[i].Check < r.Checks[j].Check
	})
	sort.SliceStable(r.Errors, func(i, j int) bool {
		if r.Errors[i].Target != r.Errors[j].Target {
			return r.Errors[i].Target < r.Errors[j].Target
		}
		return r.Errors[i].Check < r.Errors[j].Check
	})

	// Recount from scratch, but keep any grade already assigned. Grading is a
	// policy decision made by the caller, not something the counts imply, and
	// Finalise may legitimately be called more than once before output.
	grade, gradeVersion := r.Summary.Grade, r.Summary.GradeVersion
	r.Summary = Summary{Grade: grade, GradeVersion: gradeVersion}
	for _, f := range r.Findings {
		if f.Suppressed {
			r.Summary.Suppressed++
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			r.Summary.Critical++
		case SeverityHigh:
			r.Summary.High++
		case SeverityMedium:
			r.Summary.Medium++
		case SeverityLow:
			r.Summary.Low++
		case SeverityInfo:
			r.Summary.Info++
		}
		r.Summary.Total++
	}
	if r.FinishedAt.IsZero() {
		r.FinishedAt = time.Now().UTC()
	}
}

// MaxSeverity returns the highest severity among unsuppressed findings, and
// whether any such finding exists.
func (r *Result) MaxSeverity() (Severity, bool) {
	max := SeverityInfo
	found := false
	for _, f := range r.Findings {
		if f.Suppressed {
			continue
		}
		if !found || f.Severity > max {
			max, found = f.Severity, true
		}
	}
	return max, found
}

// Filter returns a copy of the result containing only unsuppressed findings at
// or above min. Applying the threshold at source keeps output small, which
// matters when the consumer is paying by the token.
func (r *Result) Filter(min Severity) *Result {
	filtered := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Severity >= min {
			filtered = append(filtered, f)
		}
	}
	clone := *r
	clone.Findings = filtered
	clone.Finalise()
	return &clone
}

// HasFailures reports whether any check failed to complete, which the CLI maps
// to the "partial results" exit code.
func (r *Result) HasFailures() bool {
	return len(r.Errors) > 0
}

// CheckNames returns the sorted, de-duplicated set of checks that ran.
func (r *Result) CheckNames() []string {
	seen := map[string]bool{}
	var names []string
	for _, c := range r.Checks {
		if !seen[c.Check] {
			seen[c.Check] = true
			names = append(names, c.Check)
		}
	}
	sort.Strings(names)
	return names
}

// Describe renders a one-line human summary such as
// "2 high, 1 medium, 5 info". It returns "no findings" when the result is
// clean, so callers never have to special-case the empty string.
func (s Summary) Describe() string {
	parts := []string{}
	add := func(n int, label string) {
		if n > 0 {
			parts = append(parts, strconv.Itoa(n)+" "+label)
		}
	}
	add(s.Critical, "critical")
	add(s.High, "high")
	add(s.Medium, "medium")
	add(s.Low, "low")
	add(s.Info, "info")
	if len(parts) == 0 {
		parts = append(parts, "no findings")
	}
	line := strings.Join(parts, ", ")
	// The grade goes last so that the detail reads first: the counts are the
	// evidence, the grade is only the shorthand.
	if s.Grade != "" {
		line += " (grade " + s.Grade + ")"
	}
	return line
}
