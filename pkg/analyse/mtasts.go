package analyse

import (
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// MTASTSMinMaxAge is the shortest policy lifetime worth having, in seconds.
// RFC 8461 §3.2 suggests weeks; a day is the floor below which the protection
// window is too narrow to be meaningful.
const MTASTSMinMaxAge = 86400

// MTASTSRecord holds the parsed _mta-sts TXT record.
type MTASTSRecord struct {
	// ID is the policy version identifier senders key their cache on.
	ID     string
	Raw    string
	Valid  bool
	Reason string
}

// MTASTSPolicy holds the parsed policy file.
type MTASTSPolicy struct {
	// Mode is enforce, testing or none.
	Mode string
	// MX holds the host patterns, which may carry a leading "*." wildcard.
	MX []string
	// MaxAge is the policy lifetime in seconds.
	MaxAge int
	// ID is the version identifier declared in the policy file, if any.
	ID  string
	Raw string
	// Fetched reports whether the policy file was retrieved at all.
	Fetched bool
	// CertificateValid reports whether TLS validation succeeded. It is only
	// meaningful when the fetch was attempted.
	CertificateValid bool
	// Valid is false when the retrieved file could not be parsed.
	Valid  bool
	Reason string
}

// ParseMTASTSRecord parses the _mta-sts TXT record.
func ParseMTASTSRecord(record string) MTASTSRecord {
	r := MTASTSRecord{Raw: strings.TrimSpace(record)}

	tags := strings.Split(r.Raw, ";")
	if len(tags) == 0 || !strings.EqualFold(strings.TrimSpace(tags[0]), "v=STSv1") {
		r.Reason = "the record does not begin with the required v=STSv1 tag"
		return r
	}

	for _, tag := range tags[1:] {
		key, value, found := strings.Cut(strings.TrimSpace(tag), "=")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "id") {
			r.ID = strings.TrimSpace(value)
		}
	}

	r.Valid = true
	return r
}

// ParseMTASTSPolicy parses the policy file, which is a sequence of
// "key: value" lines. The mx key may appear more than once.
func ParseMTASTSPolicy(body string) MTASTSPolicy {
	p := MTASTSPolicy{Raw: body, Fetched: true}

	var sawVersion bool
	for _, line := range strings.Split(body, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch key {
		case "version":
			sawVersion = strings.EqualFold(value, "STSv1")
		case "mode":
			p.Mode = strings.ToLower(value)
		case "mx":
			if value != "" {
				p.MX = append(p.MX, strings.ToLower(value))
			}
		case "max_age":
			if n, err := strconv.Atoi(value); err == nil {
				p.MaxAge = n
			}
		case "id":
			p.ID = value
		}
	}

	if !sawVersion {
		p.Reason = "the policy does not declare version: STSv1"
		return p
	}
	if p.Mode == "" {
		p.Reason = "the policy has no mode field"
		return p
	}

	p.Valid = true
	return p
}

// MTASTSCovers reports whether a policy pattern matches a mail exchanger host.
//
// A leading "*." wildcard matches exactly one label, per RFC 8461 §4.1 — so
// "*.example.com" covers "mx.example.com" but not "a.mx.example.com". Treating
// it as a broader wildcard would silently pass a policy that senders will
// reject.
func MTASTSCovers(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")

	if pattern == "" || host == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}

	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := strings.TrimSuffix(host, suffix)
	return label != "" && !strings.Contains(label, ".")
}

// MTASTS evaluates an MTA-STS deployment.
//
// records holds the _mta-sts TXT records; policy is the retrieved policy file;
// mxHosts holds the domain's published mail exchangers. Pass a zero
// MTASTSPolicy when no fetch was attempted, which suppresses the rules that
// depend on it rather than reporting them as failures.
func MTASTS(o Origin, records []string, policy MTASTSPolicy, mxHosts []string) []finding.Finding {
	var findings []finding.Finding
	target := o.Target
	name := "_mta-sts." + strings.TrimSuffix(target, ".")

	if len(records) == 0 {
		return append(findings, finding.New("SURF-MTASTS-001", target,
			o.txtEvidence(name, "no v=STSv1 record")))
	}

	record := ParseMTASTSRecord(records[0])
	ev := o.txtEvidence(name, record.Raw)

	if !record.Valid {
		return append(findings, finding.New("SURF-MTASTS-001", target, ev).
			WithDescription("Specifically, "+record.Reason+"."))
	}

	// No fetch was attempted — under --no-network, for instance. The DNS-only
	// conclusions above still stand; the rest would be guesswork.
	if !policy.Fetched {
		return findings
	}

	if !policy.CertificateValid {
		// An invalid certificate is why the policy is inert, and is more
		// actionable than the unreachability it causes.
		return append(findings, finding.New("SURF-MTASTS-008", target, ev))
	}

	if !policy.Valid {
		f := finding.New("SURF-MTASTS-002", target, ev)
		if policy.Reason != "" {
			f = f.WithDescription("Specifically, " + policy.Reason + ".")
		}
		return append(findings, f)
	}

	switch policy.Mode {
	case "testing":
		findings = append(findings, finding.New("SURF-MTASTS-003", target, ev,
			finding.ComputedEvidence("mtasts.mode", policy.Mode)))
	case "none":
		findings = append(findings, finding.New("SURF-MTASTS-004", target, ev,
			finding.ComputedEvidence("mtasts.mode", policy.Mode)))
	}

	var uncovered []string
	for _, host := range mxHosts {
		host = strings.TrimSuffix(strings.TrimSpace(host), ".")
		if host == "" || host == "." {
			continue
		}
		covered := false
		for _, pattern := range policy.MX {
			if MTASTSCovers(pattern, host) {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, host)
		}
	}
	if len(uncovered) > 0 {
		findings = append(findings, finding.New("SURF-MTASTS-005", target, ev,
			finding.ComputedEvidence("mtasts.uncovered_mx", strings.Join(uncovered, ", ")),
			finding.ComputedEvidence("mtasts.policy_mx", strings.Join(policy.MX, ", "))).
			WithDescription("Specifically, the uncovered exchangers are "+
				namesList(uncovered)+"."))
	}

	if policy.ID != "" && record.ID != "" && policy.ID != record.ID {
		findings = append(findings, finding.New("SURF-MTASTS-006", target, ev,
			finding.ComputedEvidence("mtasts.txt_id", record.ID),
			finding.ComputedEvidence("mtasts.policy_id", policy.ID)))
	}

	if policy.MaxAge < MTASTSMinMaxAge {
		findings = append(findings, finding.New("SURF-MTASTS-007", target, ev,
			finding.ComputedEvidence("mtasts.max_age", strconv.Itoa(policy.MaxAge))))
	}

	return findings
}
