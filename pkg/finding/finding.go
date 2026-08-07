// Package finding defines the vocabulary vantage uses to report DNS security
// posture: severities, confidences, evidence, findings and the result envelope
// that wraps them.
//
// The package is deliberately free of DNS logic and MUST NOT import
// github.com/adedayo/vantage/pkg/scanner. Dependencies flow one way: checks
// produce findings, findings know nothing about checks.
package finding

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Severity expresses how much the finding should worry the reader.
type Severity int

// Severity levels, ordered so that higher is worse. The zero value is
// SeverityInfo, which is the safe default: a finding never accidentally
// presents as urgent because a field was left unset.
const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// String returns the lower-case name of the severity.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "unknown"
}

// Valid reports whether s is a defined severity level.
func (s Severity) Valid() bool {
	_, ok := severityNames[s]
	return ok
}

// ParseSeverity converts a name such as "high" into a Severity. It is
// case-insensitive and tolerates surrounding whitespace.
func ParseSeverity(s string) (Severity, error) {
	want := strings.ToLower(strings.TrimSpace(s))
	for sev, name := range severityNames {
		if name == want {
			return sev, nil
		}
	}
	return SeverityInfo, fmt.Errorf("error: unknown severity %q (want one of: info, low, medium, high, critical)", s)
}

// MarshalJSON renders the severity as its lower-case name, so that structured
// output is readable and stable rather than an opaque integer.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON accepts the lower-case name produced by MarshalJSON.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	parsed, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// Confidence expresses how strongly the evidence supports the finding.
//
// This matters more than it may appear. A finding derived from inference —
// probing common DKIM selectors, matching a takeover fingerprint without
// corroboration — must not be presented with the same weight as one derived
// from an observed record, or consumers (particularly automated ones) will act
// on conclusions the evidence does not support.
type Confidence int

// Confidence levels, ordered so that higher is stronger.
const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

var confidenceNames = map[Confidence]string{
	ConfidenceLow:    "low",
	ConfidenceMedium: "medium",
	ConfidenceHigh:   "high",
}

// String returns the lower-case name of the confidence level.
func (c Confidence) String() string {
	if name, ok := confidenceNames[c]; ok {
		return name
	}
	return "unknown"
}

// Valid reports whether c is a defined confidence level.
func (c Confidence) Valid() bool {
	_, ok := confidenceNames[c]
	return ok
}

// ParseConfidence converts a name such as "medium" into a Confidence.
func ParseConfidence(s string) (Confidence, error) {
	want := strings.ToLower(strings.TrimSpace(s))
	for conf, name := range confidenceNames {
		if name == want {
			return conf, nil
		}
	}
	return ConfidenceLow, fmt.Errorf("error: unknown confidence %q (want one of: low, medium, high)", s)
}

// MarshalJSON renders the confidence as its lower-case name.
func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// UnmarshalJSON accepts the lower-case name produced by MarshalJSON.
func (c *Confidence) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	parsed, err := ParseConfidence(name)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// Evidence records an observation that justifies a finding. Findings must carry
// enough evidence for a reader to reach the same conclusion without re-running
// the tool.
type Evidence struct {
	// Kind categorises the observation: "dns-record", "http-response" or
	// "computed" for values derived by the tool (such as an SPF lookup count).
	Kind string `json:"kind"`
	// Name is the query name or URL the observation came from.
	Name string `json:"name,omitempty"`
	// Type is the DNS record type, where applicable.
	Type string `json:"type,omitempty"`
	// Value is the observed data.
	Value string `json:"value"`
	// Source identifies the resolver or endpoint that supplied the value.
	Source string `json:"source,omitempty"`
}

// DNSEvidence is a convenience constructor for record-derived evidence.
func DNSEvidence(name, rrtype, value, source string) Evidence {
	return Evidence{Kind: "dns-record", Name: name, Type: rrtype, Value: value, Source: source}
}

// ComputedEvidence is a convenience constructor for values the tool derived
// rather than observed directly.
func ComputedEvidence(name, value string) Evidence {
	return Evidence{Kind: "computed", Name: name, Value: value}
}

// Finding is a single assessed observation about a target.
type Finding struct {
	// ID is the stable catalogue identifier, e.g. "SURF-SPF-004". IDs are
	// permanent: once published, an ID is never reassigned or redefined.
	ID string `json:"id"`
	// Title is a short human-readable summary.
	Title string `json:"title"`
	// Severity is normally the catalogue default, adjusted only when context
	// justifies it. Any adjustment is explained in Description.
	Severity Severity `json:"severity"`
	// Confidence reflects how strongly the evidence supports the conclusion.
	Confidence Confidence `json:"confidence"`
	// Target is the domain or fully-qualified host assessed.
	Target string `json:"target"`
	// Check names the producing check, e.g. "spf".
	Check string `json:"check"`
	// Description explains what was found and why it matters.
	Description string `json:"description"`
	// Evidence justifies the finding.
	Evidence []Evidence `json:"evidence,omitempty"`
	// Basis names how a derived conclusion was reached, when the finding rests
	// on an inference rather than a direct observation.
	//
	// It is separate from Evidence because Evidence is what was seen, and a
	// statement of method is not. Carrying method as though it were an
	// observation puts "mimecast.com" and "registrable domain of the exchanger
	// names" in the same register, which reads as though the tool measured
	// both — and leaves the reader to work out that one is a caveat on the
	// other. Keeping it separate also lets a consumer present the caveat
	// differently, or omit it, without string-matching key names.
	Basis string `json:"basis,omitempty"`
	// Remediation describes how to fix the issue. Sourced from the catalogue so
	// that guidance is reviewed and version-controlled.
	Remediation string `json:"remediation,omitempty"`
	// References cite the controlling standards.
	References []string `json:"references,omitempty"`
	// Tags carry compliance control mappings.
	Tags []string `json:"tags,omitempty"`
	// Suppressed marks a finding matched by a suppression rule. Suppressed
	// findings are still reported so that nothing is hidden from an auditor.
	Suppressed bool `json:"suppressed,omitempty"`
	// SuppressionReason records why, when Suppressed is true.
	SuppressionReason string `json:"suppression_reason,omitempty"`
	// FirstSeen is populated when comparing against a baseline.
	FirstSeen *time.Time `json:"first_seen,omitempty"`
}

// New builds a Finding from its catalogue entry, so that title, severity,
// remediation and references never have to be repeated at the call site. It
// panics if id is not in the catalogue: an unknown ID is a programming error
// that must be caught by tests, not surfaced to a user at runtime.
func New(id, target string, evidence ...Evidence) Finding {
	entry, ok := Lookup(id)
	if !ok {
		panic(fmt.Sprintf("finding: unknown catalogue ID %q", id))
	}
	return Finding{
		ID:          entry.ID,
		Title:       entry.Title,
		Severity:    entry.Severity,
		Confidence:  entry.Confidence,
		Target:      target,
		Check:       entry.Check,
		Description: entry.Description,
		Evidence:    evidence,
		Remediation: entry.Remediation,
		References:  entry.References,
		Tags:        entry.Tags,
	}
}

// WithSeverity returns a copy of f with an adjusted severity. The reason is
// appended to the description, because a severity that differs from the
// catalogue default must be explained to be trustworthy.
func (f Finding) WithSeverity(s Severity, reason string) Finding {
	f.Severity = s
	if reason != "" {
		f.Description = strings.TrimSpace(f.Description) + " " + strings.TrimSpace(reason)
	}
	return f
}

// WithConfidence returns a copy of f with an adjusted confidence level.
func (f Finding) WithConfidence(c Confidence) Finding {
	f.Confidence = c
	return f
}

// WithDescription returns a copy of f with additional context appended to the
// catalogue description.
func (f Finding) WithDescription(extra string) Finding {
	if extra != "" {
		f.Description = strings.TrimSpace(f.Description) + " " + strings.TrimSpace(extra)
	}
	return f
}

// WithBasis returns a copy of f recording how a derived conclusion was reached.
func (f Finding) WithBasis(basis string) Finding {
	f.Basis = strings.TrimSpace(basis)
	return f
}

// WithEvidence returns a copy of f with further evidence appended.
func (f Finding) WithEvidence(e ...Evidence) Finding {
	f.Evidence = append(append([]Evidence{}, f.Evidence...), e...)
	return f
}
