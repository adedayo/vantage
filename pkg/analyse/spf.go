// Package analyse turns retrieved DNS records into findings.
//
// Every function here is a pure function of the records it is given: no DNS
// queries, no clock, no network. That keeps the security judgement — the part
// that is easy to get subtly wrong — exhaustively testable without a resolver,
// and keeps retrieval and interpretation independently reviewable.
//
// Rules requiring further lookups (SPF include recursion and the ten-lookup
// limit, DMARC organisational-domain fallback, external destination
// verification) are specified in spec 011 and live alongside their queries.
package analyse

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// Origin identifies what was assessed and where the data came from.
//
// Carrying the answering resolver through to the evidence is what makes a
// finding reproducible. A reader querying from elsewhere may legitimately see
// different answers — split-horizon DNS, filtering, or an outright hijack — and
// without attribution they cannot tell a stale result from a real discrepancy.
type Origin struct {
	// Target is the domain assessed.
	Target string
	// Source is the resolver that answered, as "host:port". It may be empty
	// when the caller did not record it.
	Source string
}

// txtEvidence builds TXT record evidence attributed to the origin's resolver.
// SPF and DMARC are both published as TXT, so the record type is implicit.
func (o Origin) txtEvidence(name, value string) finding.Evidence {
	return finding.DNSEvidence(name, "TXT", value, o.Source)
}

// SPF evaluates the SPF records published by a domain.
//
// records must contain every TXT record beginning with "v=spf1"; pass an empty
// slice to report absence. hasMail indicates whether the domain publishes MX
// records or otherwise appears to send mail, which governs how seriously a
// missing record is treated.
func SPF(o Origin, records []string, hasMail bool) []finding.Finding {
	var findings []finding.Finding
	target := o.Target
	name := target

	if len(records) == 0 {
		f := finding.New("SURF-SPF-001", target,
			o.txtEvidence(name, "no v=spf1 record"))
		if !hasMail {
			// A domain that does not send mail is a far smaller spoofing prize,
			// and a null MX is the correct control for it. Reporting this as
			// High would train operators to ignore the finding.
			f = f.WithSeverity(finding.SeverityLow,
				"Severity reduced because the domain publishes no MX records and appears not to send mail; "+
					"publishing `v=spf1 -all` alongside a null MX remains good practice.")
		}
		return append(findings, f)
	}

	if len(records) > 1 {
		findings = append(findings, finding.New("SURF-SPF-002", target,
			o.txtEvidence(name, strings.Join(records, " | ")),
			finding.ComputedEvidence("spf.record_count", strconv.Itoa(len(records)))))
	}

	// Evaluate the first record. When several exist the domain is already
	// broken (SURF-SPF-002); analysing the first still surfaces the content
	// problems the operator will need to fix once they merge them.
	record := records[0]
	ev := o.txtEvidence(name, record)

	switch terminal(record) {
	case "+all", "all":
		findings = append(findings, finding.New("SURF-SPF-004", target, ev))
	case "?all":
		findings = append(findings, finding.New("SURF-SPF-003", target, ev,
			finding.ComputedEvidence("spf.terminal", "?all")))
	case "~all":
		findings = append(findings, finding.New("SURF-SPF-005", target, ev))
	case "-all":
		// Correctly configured; no finding.
	case "":
		if !hasRedirect(record) {
			findings = append(findings, finding.New("SURF-SPF-003", target, ev,
				finding.ComputedEvidence("spf.terminal", "none")))
		}
	}

	if mechanism, ok := hasPTR(record); ok {
		findings = append(findings, finding.New("SURF-SPF-008", target, ev,
			finding.ComputedEvidence("spf.mechanism", mechanism)).
			WithDescription("Specifically, the mechanism is `"+mechanism+"`."))
	}

	for _, cidr := range broadRanges(record) {
		// broadRanges already renders the prefix with its size, so the
		// sentence quotes nothing: backticks around "10.0.0.0/8 (16777216
		// addresses)" would mark the prose as though it were the term.
		findings = append(findings, finding.New("SURF-SPF-011", target, ev,
			finding.ComputedEvidence("spf.broad_range", cidr)).
			WithDescription("Specifically, the range is "+cidr+"."))
	}

	return findings
}

// terminal returns the record's terminal "all" mechanism, lower-cased and
// including its qualifier, or "" when the record has none.
func terminal(record string) string {
	var last string
	for _, term := range strings.Fields(record) {
		t := strings.ToLower(term)
		bare := strings.TrimLeft(t, "+-~?")
		if bare == "all" {
			last = t
		}
	}
	return last
}

// hasRedirect reports whether the record delegates evaluation with redirect=,
// in which case the absence of an "all" mechanism is correct rather than a
// defect.
func hasRedirect(record string) bool {
	for _, term := range strings.Fields(record) {
		if strings.HasPrefix(strings.ToLower(term), "redirect=") {
			return true
		}
	}
	return false
}

// hasPTR reports whether the record uses the deprecated ptr mechanism.
func hasPTR(record string) (string, bool) {
	for _, term := range strings.Fields(record) {
		t := strings.ToLower(term)
		bare := strings.TrimLeft(t, "+-~?")
		if bare == "ptr" || strings.HasPrefix(bare, "ptr:") {
			return term, true
		}
	}
	return "", false
}

// broadRanges returns ip4/ip6 mechanisms authorising more addresses than is
// prudent. The thresholds (/16 for IPv4, /32 for IPv6) are deliberately
// generous: the intent is to catch a whole hosting provider being authorised,
// not to quibble about a /24.
func broadRanges(record string) []string {
	var broad []string
	for _, term := range strings.Fields(record) {
		t := strings.ToLower(strings.TrimLeft(term, "+-~?"))
		var value string
		switch {
		case strings.HasPrefix(t, "ip4:"):
			value = strings.TrimPrefix(t, "ip4:")
		case strings.HasPrefix(t, "ip6:"):
			value = strings.TrimPrefix(t, "ip6:")
		default:
			continue
		}
		if !strings.Contains(value, "/") {
			continue // a single address is not a range
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		switch {
		case bits == 32 && ones < 16:
			broad = append(broad, fmt.Sprintf("%s (%d addresses)", value, 1<<uint(32-ones)))
		case bits == 128 && ones < 32:
			broad = append(broad, value)
		}
	}
	return broad
}
