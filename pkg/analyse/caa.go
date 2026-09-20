package analyse

import (
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// CAARecord is a single parsed CAA property.
type CAARecord struct {
	// Flags is the issuer flags octet; bit 0 is the critical flag.
	Flags uint8
	// Tag is the property tag, lowercased: issue, issuewild, iodef, …
	Tag string
	// Value is the property value with surrounding quotes removed.
	Value string
}

// Critical reports whether the issuer critical flag is set. A CA that does not
// recognise a critical property must refuse to issue.
func (c CAARecord) Critical() bool { return c.Flags&0x80 != 0 }

// knownCAATags are the properties defined by RFC 8659. A critical flag on
// anything else blocks issuance outright.
var knownCAATags = map[string]bool{"issue": true, "issuewild": true, "iodef": true}

// CAAPolicy is the outcome of the RFC 8659 §3 tree-climbing search: the records
// in force and the label that supplied them.
type CAAPolicy struct {
	// Records is the policy set found at Source, empty if none was found.
	Records []CAARecord
	// Source is the domain whose CAA record set applies.
	Source string
	// Inherited is true when Source is an ancestor rather than the target.
	Inherited bool
}

// ParseCAA parses CAA records presented as "<flags> <tag> <value>", the form
// used by dig and by this tool's retrieval helpers.
func ParseCAA(records []string) []CAARecord {
	var parsed []CAARecord
	for _, r := range records {
		fields := strings.Fields(strings.TrimSpace(r))
		if len(fields) < 3 {
			continue
		}

		var flags uint8
		// A malformed flags field is treated as zero rather than discarded:
		// the properties still describe policy, and dropping the record would
		// silently understate what is published.
		for _, ch := range fields[0] {
			if ch < '0' || ch > '9' {
				flags = 0
				break
			}
			flags = flags*10 + uint8(ch-'0')
		}

		parsed = append(parsed, CAARecord{
			Flags: flags,
			Tag:   strings.ToLower(fields[1]),
			Value: strings.Trim(strings.Join(fields[2:], " "), `"`),
		})
	}
	return parsed
}

// CAA evaluates a CAA policy found by tree-climbing.
func CAA(o Origin, policy CAAPolicy) []finding.Finding {
	var findings []finding.Finding
	target := o.Target

	if len(policy.Records) == 0 {
		return append(findings, finding.New("SURF-CAA-001", target,
			finding.ComputedEvidence("caa.searched", target)))
	}

	source := policy.Source
	if source == "" {
		source = target
	}
	ev := finding.ComputedEvidence("caa.source", source)

	if policy.Inherited {
		findings = append(findings, finding.New("SURF-CAA-005", target, ev))
	}

	var hasIssue, hasIssueWild, hasIodef bool
	for _, r := range policy.Records {
		switch r.Tag {
		case "issue":
			hasIssue = true
		case "issuewild":
			hasIssueWild = true
		case "iodef":
			hasIodef = true
		}

		if r.Critical() && !knownCAATags[r.Tag] {
			findings = append(findings, finding.New("SURF-CAA-004", target, ev,
				finding.ComputedEvidence("caa.tag", r.Tag),
				finding.ComputedEvidence("caa.flags", "critical")).
				WithDescription("Specifically, the unrecognised tag is `"+r.Tag+"`."))
		}
	}

	if hasIssue && !hasIssueWild {
		findings = append(findings, finding.New("SURF-CAA-002", target, ev))
	}

	if !hasIodef {
		findings = append(findings, finding.New("SURF-CAA-003", target, ev))
	}

	return findings
}

// CAAAncestors returns the names to query, in the order RFC 8659 §3 requires:
// the domain itself, then each parent up to but not including the public
// suffix. Issuance policy is not inherited from a public suffix, so climbing
// into one would attribute a registry's policy to an unrelated registrant.
func CAAAncestors(domain, publicSuffix string) []string {
	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	publicSuffix = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(publicSuffix)), ".")

	if domain == "" || domain == publicSuffix {
		return nil
	}

	var names []string
	for name := domain; name != ""; {
		names = append(names, name)

		_, rest, found := strings.Cut(name, ".")
		if !found || rest == "" || rest == publicSuffix {
			break
		}
		name = rest
	}
	return names
}
