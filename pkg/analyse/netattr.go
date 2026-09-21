package analyse

import (
	"sort"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/netattr"
	"github.com/adedayo/vantage/pkg/observation"
)

// NetworkHost is the structured fact of one resolved name and its
// attributions. It lives in pkg/observation so consumers can read it without
// importing the judgement rules, and is aliased here so this package and every
// existing caller continue to name it as before.
//
// An alias rather than a copy: two types meaning the same thing is how a
// consumer ends up converting between them by hand.
type NetworkHost = observation.NetworkHost

// NetworkObservation is everything retrieval gathered for the attribution
// rules.
type NetworkObservation struct {
	// Domain is the zone assessed.
	Domain string
	// Hosts are the names examined.
	Hosts []NetworkHost
	// Estate is the set of providers the domain's own apex and mail
	// infrastructure sit in. It is derived rather than declared, so the check
	// needs no configuration to have an opinion about what "outside the
	// estate" means.
	Estate map[string]bool
	// ExpectedJurisdictions are the ISO 3166-1 alpha-2 countries the operator
	// declared their infrastructure should be in. Empty means no expectation
	// was stated, and the jurisdiction rule is then not evaluated at all.
	ExpectedJurisdictions []string
	// FailedSources names the provider range publications that could not be
	// loaded, so the report can say which attributions were not possible.
	//
	// This is the check's most dangerous failure mode and the reason the list
	// is carried rather than a bare flag. Coverage gaps produce false
	// negatives, not false positives: if the AWS ranges are unavailable, every
	// AWS address reads as "unattributed", SURF-NET-001 quietly stops firing,
	// and the report is indistinguishable from a domain that genuinely uses no
	// third-party hosting. Silence would be a claim the data does not support.
	FailedSources []string
	// StaleSources names the publications served from a cache entry older than
	// its lifetime, because the operator's endpoint could not be reached. The
	// attributions are still usable — a prefix that moved last week is almost
	// always still announced by the same operator — but a reader comparing two
	// runs deserves to know the basis was not refreshed.
	StaleSources []string
	// Provenance records where each provider's ranges came from and when.
	// Attribution can change without the domain changing, so a consumer
	// diffing two runs needs the data's origin and age to tell the two apart.
	Provenance []string
}

// CoverageComplete reports that every provider range publication loaded.
func (o NetworkObservation) CoverageComplete() bool { return len(o.FailedSources) == 0 }

// NetworkAttribution evaluates where a domain's hosts actually live.
func NetworkAttribution(o Origin, obs NetworkObservation) []finding.Finding {
	var findings []finding.Finding
	expected := jurisdictionSet(obs.ExpectedJurisdictions)

	for _, h := range obs.Hosts {
		// Special-purpose addresses are assessed individually: each one is a
		// distinct disclosure, and there are never many.
		for _, a := range h.Attributions {
			if a.Special != nil {
				findings = append(findings, specialFindings(o, a, []finding.Evidence{
					finding.DNSEvidence(h.Host, "A/AAAA", a.Address.String(), o.Source),
					finding.ComputedEvidence("net.role", h.Role),
				})...)
			}
		}

		// Provider rules are assessed once per host per provider. A host with
		// four A records in one region is one fact about that host, and
		// reporting it four times buries everything else in the report.
		for _, group := range groupByProvider(h) {
			findings = append(findings, assessProvider(o, obs, h, group, expected)...)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// providerGroup is every address of one host attributed to one provider.
type providerGroup struct {
	provider  string
	addresses []netattr.Attribution
}

// groupByProvider collects a host's addresses by the provider announcing them,
// preserving first-seen order so output is stable.
func groupByProvider(h NetworkHost) []providerGroup {
	var order []string
	byProvider := map[string][]netattr.Attribution{}

	for _, a := range h.Attributions {
		// An address in special-purpose space is not in a cloud, and an
		// unattributed address establishes nothing: provider coverage is
		// incomplete by construction, so "not attributed" and "not in a cloud"
		// are indistinguishable and must not be conflated.
		if a.Special != nil || a.Provider == "" {
			continue
		}
		if _, seen := byProvider[a.Provider]; !seen {
			order = append(order, a.Provider)
		}
		byProvider[a.Provider] = append(byProvider[a.Provider], a)
	}

	groups := make([]providerGroup, 0, len(order))
	for _, p := range order {
		groups = append(groups, providerGroup{provider: p, addresses: byProvider[p]})
	}
	return groups
}

// assessProvider applies the provider rules to one host's addresses at one
// provider.
func assessProvider(
	o Origin, obs NetworkObservation, h NetworkHost,
	group providerGroup, expected map[string]bool,
) []finding.Finding {
	evidence := make([]finding.Evidence, 0, len(group.addresses)+4)
	for _, a := range group.addresses {
		evidence = append(evidence,
			finding.DNSEvidence(h.Host, "A/AAAA", a.Address.String(), o.Source))
	}

	first := group.addresses[0]
	evidence = append(evidence,
		finding.ComputedEvidence("net.role", h.Role),
		finding.ComputedEvidence("net.provider", group.provider),
		finding.ComputedEvidence("net.prefix", prefixList(group.addresses)),
		finding.ComputedEvidence("net.source", first.Source))
	if regions := regionList(group.addresses); regions != "" {
		evidence = append(evidence, finding.ComputedEvidence("net.region", regions))
	}

	var findings []finding.Finding

	if len(obs.Estate) > 0 && !obs.Estate[group.provider] {
		findings = append(findings, finding.New("SURF-NET-001", o.Target, evidence...).
			WithConfidence(finding.ConfidenceMedium).
			WithDescription("This host is served from a provider that hosts none of the "+
				"domain's own apex or mail infrastructure. That is normal for a deliberate "+
				"third-party service and worth knowing about when it is not: it is how "+
				"shadow IT and forgotten migrations appear in DNS."))
	}

	// The jurisdiction rule is evaluated only when an expectation was stated
	// and the region is known. Without both there is nothing to compare, and a
	// finding drawn from a default assumption about where an organisation
	// "should" be would be an invention.
	for _, j := range unexpectedJurisdictions(group.addresses, expected) {
		findings = append(findings, finding.New("SURF-NET-003", o.Target,
			append(evidence,
				finding.ComputedEvidence("net.jurisdiction", j),
				finding.ComputedEvidence("net.expected_jurisdictions",
					strings.Join(sortedKeys(expected), ", ")))...))
	}

	return findings
}

// prefixList renders the distinct prefixes behind a group, so the evidence
// still shows which range each attribution came from.
func prefixList(addresses []netattr.Attribution) string {
	return joinDistinct(addresses, func(a netattr.Attribution) string { return a.Prefix.String() })
}

// regionList renders the distinct regions behind a group. A host answering
// from several regions is ordinary for a global service, and collapsing that
// to one region would misrepresent it.
func regionList(addresses []netattr.Attribution) string {
	return joinDistinct(addresses, func(a netattr.Attribution) string { return a.Region })
}

// joinDistinct renders each distinct non-empty value once, in first-seen order.
func joinDistinct(addresses []netattr.Attribution, key func(netattr.Attribution) string) string {
	var out []string
	seen := map[string]bool{}
	for _, a := range addresses {
		v := key(a)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return strings.Join(out, ", ")
}

// unexpectedJurisdictions returns each distinct jurisdiction in the group that
// the caller did not expect, in first-seen order.
func unexpectedJurisdictions(
	addresses []netattr.Attribution, expected map[string]bool,
) []string {
	if len(expected) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range addresses {
		if a.Jurisdiction == "" || expected[a.Jurisdiction] || seen[a.Jurisdiction] {
			continue
		}
		seen[a.Jurisdiction] = true
		out = append(out, a.Jurisdiction)
	}
	return out
}

// specialFindings reports an address from the special-purpose registries.
func specialFindings(
	o Origin, a netattr.Attribution, evidence []finding.Evidence,
) []finding.Finding {
	sr := a.Special
	evidence = append(evidence,
		finding.ComputedEvidence("net.range", sr.Prefix.String()),
		finding.ComputedEvidence("net.range_name", sr.Name),
		finding.ComputedEvidence("net.category", string(sr.Category)))

	if sr.Category.DisclosesInternalAddressing() {
		return []finding.Finding{finding.New("SURF-NET-002", o.Target, evidence...)}
	}

	switch sr.Category {
	case netattr.CategoryLoopback, netattr.CategoryUnspecified:
		// Pointing a name at the loopback or the unspecified address is a
		// recognised way of making a name exist without it resolving anywhere.
		// It is reported so the reader can confirm it was deliberate, not
		// asserted as a leak.
		return []finding.Finding{
			finding.New("SURF-NET-002", o.Target, evidence...).
				WithConfidence(finding.ConfidenceLow).
				WithDescription("The name resolves to an address that goes nowhere. This is " +
					"often deliberate - null-routing a name that must exist without pointing " +
					"it at a host - and is reported for confirmation rather than as a defect."),
		}
	case netattr.CategoryDocumentation, netattr.CategoryReserved:
		return []finding.Finding{
			finding.New("SURF-NET-002", o.Target, evidence...).
				WithConfidence(finding.ConfidenceMedium).
				WithDescription("The name resolves into address space reserved for " +
					"documentation or future use, which is never routable. This is almost " +
					"always a placeholder that was never replaced with a real address."),
		}
	default:
		// Multicast, broadcast and protocol assignments in an A record are
		// certainly wrong, but they are a functional defect rather than a
		// disclosure, and this check's remit is attribution.
		return nil
	}
}

// jurisdictionSet normalises the declared expectation.
func jurisdictionSet(codes []string) map[string]bool {
	if len(codes) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, c := range codes {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			set[c] = true
		}
	}
	return set
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// NetworkRecords renders what was attributed, so a reader sees the whole
// picture rather than only the exceptions.
func NetworkRecords(obs NetworkObservation) []string {
	records := make([]string, 0,
		len(obs.Hosts)+len(obs.FailedSources)+len(obs.StaleSources)+len(obs.Provenance))

	// The coverage warning comes first, because everything below it is
	// conditional on it. A reader who sees "unattributed" without knowing a
	// source was missing has been misled by omission.
	for _, src := range obs.FailedSources {
		records = append(records,
			finding.RecordPrefixWarning+
				" provider ranges unavailable, attribution incomplete: "+src)
	}
	for _, src := range obs.StaleSources {
		records = append(records,
			finding.RecordPrefixWarning+
				" provider ranges could not be refreshed, using cached data: "+src)
	}

	// Provenance follows the warnings and precedes the data, so a reader sees
	// what the attributions below were derived from.
	for _, p := range obs.Provenance {
		records = append(records, finding.RecordPrefixProvenance+" "+p)
	}

	for _, h := range obs.Hosts {
		for _, a := range h.Attributions {
			line := h.Host + " " + a.Address.String()
			switch {
			case a.Special != nil:
				line += " (" + a.Special.Name + ")"
			case a.Provider != "":
				line += " (" + a.Provider
				if a.Region != "" {
					line += ", " + a.Region
				}
				line += ")"
			case !obs.CoverageComplete():
				// Not "unattributed": that asserts the address belongs to no
				// known provider, which is precisely what could not be
				// established while a source was missing.
				line += " (not attributed - coverage incomplete)"
			default:
				line += " (unattributed)"
			}
			records = append(records, line)
		}
	}
	return records
}
