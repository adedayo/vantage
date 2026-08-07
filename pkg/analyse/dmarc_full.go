package analyse

import (
	"context"
	"errors"
	"strings"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/finding"
)

// DMARCResolver supplies the lookups that organisational-domain fallback and
// external-destination verification require. It is an interface for the same
// reason the SPF evaluator takes one: the judgement stays testable without a
// network.
type DMARCResolver interface {
	// TXT returns the TXT records published at a name.
	TXT(ctx context.Context, name string) ([]string, error)
}

// OrganisationalDomain returns the registrable domain for a name, given its
// public suffix — the domain whose DMARC policy a subdomain inherits.
func OrganisationalDomain(domain, publicSuffix string) string {
	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	publicSuffix = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(publicSuffix)), ".")

	if domain == "" || publicSuffix == "" || domain == publicSuffix {
		return domain
	}
	if !strings.HasSuffix(domain, "."+publicSuffix) {
		return domain
	}

	// The organisational domain is the public suffix plus one label.
	prefix := strings.TrimSuffix(domain, "."+publicSuffix)
	labels := strings.Split(prefix, ".")
	return labels[len(labels)-1] + "." + publicSuffix
}

// dmarcRecords filters a TXT set down to DMARC records.
func dmarcRecords(txts []string) []string {
	var records []string
	for _, txt := range txts {
		if txt = strings.TrimSpace(txt); strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			records = append(records, txt)
		}
	}
	return records
}

// isAbsence reports whether an error means the name definitively has no
// record, as distinct from the lookup having failed to answer at all.
//
// The distinction decides whether a finding may be raised. NXDOMAIN and an
// empty answer are conclusions about the target; a timeout, an unreachable
// resolver, or an embedder's scope guard refusing the egress are conclusions
// about the lookup, and nothing about the target follows from them.
//
// The substring fallback exists because DMARCResolver is a consumer-supplied
// interface: an implementation that predates the sentinels, or that wraps
// another library's error, still signals absence in the only vocabulary it
// has. Matching the sentinel first means a conforming implementation is never
// classified by its wording.
func isAbsence(err error) bool {
	if errors.Is(err, vantage.ErrNotFound) {
		return true
	}
	// Never treat a withheld or refused lookup as an absence, whatever its
	// message happens to contain.
	if errors.Is(err, vantage.ErrOutOfScope) ||
		errors.Is(err, vantage.ErrNetworkDisabled) ||
		errors.Is(err, vantage.ErrResolverUnreachable) {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

// DMARCFull evaluates DMARC with the two rules that need further lookups:
// organisational-domain fallback and external-destination authorisation.
//
// records must hold the DMARC records at _dmarc.<domain>; pass an empty slice
// to report absence. orgDomain is the registrable domain, as computed by
// OrganisationalDomain.
func DMARCFull(ctx context.Context, o Origin, r DMARCResolver, records []string, orgDomain string) []finding.Finding {
	target := strings.TrimSuffix(strings.ToLower(o.Target), ".")
	orgDomain = strings.TrimSuffix(strings.ToLower(orgDomain), ".")

	// A subdomain with no record of its own inherits the organisational
	// domain's policy. Reporting "no DMARC record" would be wrong: receivers
	// do apply a policy to this name.
	if len(records) == 0 && r != nil && orgDomain != "" && orgDomain != target {
		txts, err := r.TXT(ctx, "_dmarc."+orgDomain)
		if err == nil {
			if inherited := dmarcRecords(txts); len(inherited) > 0 {
				findings := []finding.Finding{
					finding.New("SURF-DMARC-009", o.Target,
						o.txtEvidence("_dmarc."+orgDomain, inherited[0]),
						finding.ComputedEvidence("dmarc.organisational_domain", orgDomain)),
				}
				// The inherited policy governs this name, so its weaknesses
				// are this name's weaknesses too.
				return append(findings, DMARC(Origin{Target: o.Target, Source: o.Source}, inherited)...)
			}
		}
	}

	findings := DMARC(o, records)
	if len(records) == 0 || r == nil {
		return findings
	}

	policy := ParseDMARC(records[0])
	if !policy.Valid {
		return findings
	}

	ev := o.txtEvidence("_dmarc."+target, policy.Raw)
	checked := map[string]bool{}

	for _, uri := range append(append([]string{}, policy.RUA...), policy.RUF...) {
		dest := reportDestination(uri)
		if dest == "" || checked[dest] {
			continue
		}
		checked[dest] = true

		// Destinations within the domain need no authorisation record.
		if dest == target || strings.HasSuffix(dest, "."+target) {
			continue
		}

		name := target + "._report._dmarc." + dest
		txts, err := r.TXT(ctx, name)
		if err != nil && !isAbsence(err) {
			// The lookup did not answer, so nothing is known about this
			// destination. Reporting the record as missing would state as fact
			// something that was never established — and it is the costlier
			// direction of the two, because it sends an operator to repair
			// configuration that may well be correct.
			//
			// This is the same reasoning that makes a nil resolver return
			// early rather than raise: an unasked question and an unanswered
			// one are both silence, and silence is not evidence.
			continue
		}
		if len(dmarcRecords(txts)) == 0 {
			findings = append(findings, finding.New("SURF-DMARC-006", o.Target, ev,
				finding.ComputedEvidence("dmarc.report_destination", dest),
				finding.ComputedEvidence("dmarc.authorisation_record", name)))
		}
	}

	return findings
}

// reportDestination extracts the domain from a DMARC reporting URI, which is a
// mailto: address possibly carrying an !size limit.
func reportDestination(uri string) string {
	uri = strings.TrimSpace(uri)
	if i := strings.IndexByte(uri, '!'); i >= 0 {
		uri = uri[:i]
	}
	if !strings.HasPrefix(strings.ToLower(uri), "mailto:") {
		return ""
	}
	_, host, found := strings.Cut(uri[len("mailto:"):], "@")
	if !found {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
