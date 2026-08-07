package analyse

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// Nameserver is one authoritative server, together with what querying it
// directly revealed.
//
// The distinction between Answered and Authoritative carries the whole weight
// of the lame-delegation rule, so the two are recorded separately rather than
// collapsed into a single "healthy" boolean.
type Nameserver struct {
	// Host is the name published in the NS set, without a trailing dot.
	Host string
	// Addresses are the A and AAAA records the host resolves to.
	Addresses []string
	// Answered reports whether the server replied to a direct query at all.
	Answered bool
	// Authoritative reports whether it set the AA bit for the zone's SOA.
	Authoritative bool
	// Serial is the SOA serial it returned, when it returned one.
	Serial uint32
	// HasSerial distinguishes serial zero from no answer.
	HasSerial bool
	// Provider is the registrable domain of the nameserver's own name, used to
	// group servers that plausibly replicate from one another. Retrieval fills
	// it in; an empty value groups the server with every other ungrouped one.
	Provider string
	// RecursionTested records that the open-recursion probe was performed, so
	// that a probe which failed is never read as a clean result.
	RecursionTested bool
	// OpenRecursive reports whether it recursively resolved a foreign name.
	OpenRecursive bool
}

// Delegation is everything retrieval learned about a zone's delegation.
type Delegation struct {
	// Domain is the zone assessed.
	Domain string
	// Nameservers is the NS set published by the zone itself.
	Nameservers []Nameserver
	// ParentNS is the NS set the parent zone delegates to.
	ParentNS []string
	// ParentChecked records that the parent was successfully consulted. A
	// parent that could not be reached leaves ParentNS empty, which must not
	// be mistaken for a parent that delegates to nothing.
	ParentChecked bool
	// Glue maps in-bailiwick nameserver names to the addresses supplied in the
	// parent's referral.
	Glue map[string][]string
}

// Delegation evaluates nameserver and delegation hygiene.
func DelegationHygiene(o Origin, d Delegation) []finding.Finding {
	var findings []finding.Finding
	target := o.Target

	if len(d.Nameservers) == 0 {
		// No NS set at all is not a hygiene problem to be graded; it means
		// retrieval found nothing, and the check reports absence instead.
		return findings
	}

	if len(d.Nameservers) == 1 {
		findings = append(findings, finding.New("SURF-NS-001", target,
			finding.DNSEvidence(d.Domain, "NS", d.Nameservers[0].Host, o.Source),
			finding.ComputedEvidence("ns.count", "1")))
	}

	findings = append(findings, singleNetwork(o, d)...)
	findings = append(findings, singleProvider(o, d)...)
	findings = append(findings, parentChildAgreement(o, d)...)
	findings = append(findings, lameDelegation(o, d)...)
	findings = append(findings, missingGlue(o, d)...)
	findings = append(findings, openRecursion(o, d)...)
	findings = append(findings, serialMismatch(o, d)...)

	return findings
}

// singleProvider reports an NS set entirely operated by one organisation.
//
// The provider is the registrable domain of each nameserver's own name. That is
// a direct observation rather than a proxy for an ASN: ns1.example-dns.net and
// ns2.example-dns.net are administered by whoever holds example-dns.net, and if
// that organisation has an outage, a billing dispute or a compromise, the zone
// goes with it. Vanity nameservers inside the zone being delegated are the case
// this cannot see through — ns1.example.com may be operated by a third party —
// so the finding is reported at reduced confidence and says what it rests on.
//
// The severity is Low on purpose. A single provider is the normal, supported
// and usually correct arrangement; this is a resilience observation for
// operators whose availability requirements justify the cost and complexity of
// a second one, not a defect.
func singleProvider(o Origin, d Delegation) []finding.Finding {
	if len(d.Nameservers) < 2 {
		// One nameserver is already reported by SURF-NS-001, and "all of the
		// single nameserver is at one provider" says nothing further.
		return nil
	}

	providers := map[string]bool{}
	var hosts []string
	for _, ns := range d.Nameservers {
		p := strings.ToLower(strings.TrimSpace(ns.Provider))
		if p == "" {
			// A nameserver whose provider could not be determined makes the
			// set unjudgeable: it may be the second provider. Concluding
			// "all one provider" from an incomplete set would be a finding
			// drawn from missing data.
			return nil
		}
		providers[p] = true
		hosts = append(hosts, ns.Host)
	}

	if len(providers) != 1 {
		return nil
	}

	var provider string
	for p := range providers {
		provider = p
	}
	sort.Strings(hosts)

	f := finding.New("SURF-NS-002", o.Target,
		finding.ComputedEvidence("ns.provider", provider),
		finding.ComputedEvidence("ns.hosts", strings.Join(hosts, ", "))).
		WithBasis("The operator is inferred from the registrable domain of the " +
			"nameserver hostnames, not observed directly.")

	// Nameservers named inside the zone they serve tell us nothing about who
	// operates them, so the claim is weaker in that case and must say so.
	if inBailiwick(d.Domain, provider) {
		f = f.WithConfidence(finding.ConfidenceLow).
			WithDescription("Every nameserver is named within the domain itself, so who operates " +
				"them cannot be determined from DNS. They may be a single provider's vanity " +
				"names or several providers'; this is reported so an operator can confirm which.")
	}

	return []finding.Finding{f}
}

// singleNetwork reports an NS set whose addresses all sit in one IPv4 /24.
//
// One nameserver is an obvious single point of failure; several nameservers on
// one subnet are the same single point of failure wearing a disguise, because
// the route, the rack and usually the power all fail together.
func singleNetwork(o Origin, d Delegation) []finding.Finding {
	if len(d.Nameservers) < 2 {
		// With one nameserver SURF-NS-001 already says everything there is to
		// say; adding a second finding for one defect is noise.
		return nil
	}

	prefixes := map[string]bool{}
	var addresses []string
	for _, ns := range d.Nameservers {
		for _, a := range ns.Addresses {
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			// IPv6 is deliberately excluded rather than approximated. A /24
			// has no IPv6 equivalent that means the same thing, and inventing
			// one would produce a finding whose reasoning cannot be defended.
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			addresses = append(addresses, a)
			prefixes[v4.Mask(net.CIDRMask(24, 32)).String()+"/24"] = true
		}
	}

	if len(addresses) < 2 || len(prefixes) != 1 {
		return nil
	}

	var prefix string
	for p := range prefixes {
		prefix = p
	}
	sort.Strings(addresses)

	return []finding.Finding{finding.New("SURF-NS-003", o.Target,
		finding.ComputedEvidence("ns.prefix", prefix),
		finding.ComputedEvidence("ns.addresses", strings.Join(addresses, ", ")))}
}

// parentChildAgreement reports a delegation that disagrees with the zone.
func parentChildAgreement(o Origin, d Delegation) []finding.Finding {
	if !d.ParentChecked || len(d.ParentNS) == 0 {
		// Silence here is the point: an unreachable parent is not evidence of
		// disagreement, and reporting it as such would put a finding on every
		// domain whose TLD servers happened to rate-limit us.
		return nil
	}

	child := hostSet(nameserverHosts(d.Nameservers))
	parent := hostSet(d.ParentNS)
	if strings.Join(child, ", ") == strings.Join(parent, ", ") {
		return nil
	}

	return []finding.Finding{finding.New("SURF-NS-004", o.Target,
		finding.ComputedEvidence("ns.parent", strings.Join(parent, ", ")),
		finding.ComputedEvidence("ns.child", strings.Join(child, ", ")))}
}

// lameDelegation reports nameservers that do not answer authoritatively.
func lameDelegation(o Origin, d Delegation) []finding.Finding {
	var findings []finding.Finding
	for _, ns := range d.Nameservers {
		if ns.Authoritative {
			continue
		}

		f := finding.New("SURF-NS-005", o.Target,
			finding.ComputedEvidence("ns.host", ns.Host),
			finding.ComputedEvidence("ns.answered", strconv.FormatBool(ns.Answered)))

		if !ns.Answered {
			// A server that said nothing may be lame, or may be behind a
			// filter between it and this vantage point. The finding stands —
			// a nameserver unreachable from here is unreachable for some
			// users too — but the confidence must not claim more than one
			// observation can support.
			f = f.WithConfidence(finding.ConfidenceMedium).
				WithDescription("The nameserver did not respond to a direct query from this " +
					"vantage point, so it may be lame or may simply be unreachable from here.")
		}
		findings = append(findings, f)
	}
	return findings
}

// missingGlue reports in-bailiwick nameservers with no address in the referral.
func missingGlue(o Origin, d Delegation) []finding.Finding {
	if !d.ParentChecked {
		return nil
	}

	var findings []finding.Finding
	for _, ns := range d.Nameservers {
		if !inBailiwick(d.Domain, ns.Host) {
			continue
		}
		if len(d.Glue[strings.ToLower(ns.Host)]) > 0 {
			continue
		}
		findings = append(findings, finding.New("SURF-NS-006", o.Target,
			finding.ComputedEvidence("ns.host", ns.Host)))
	}
	return findings
}

// openRecursion reports nameservers that resolve foreign names for anybody.
func openRecursion(o Origin, d Delegation) []finding.Finding {
	var findings []finding.Finding
	for _, ns := range d.Nameservers {
		if !ns.RecursionTested || !ns.OpenRecursive {
			continue
		}
		findings = append(findings, finding.New("SURF-NS-007", o.Target,
			finding.ComputedEvidence("ns.host", ns.Host)))
	}
	return findings
}

// serialMismatch reports nameservers serving different versions of the zone.
//
// Serials are compared only within a provider, never across providers. A zone
// served by two independent operators — an increasingly common and thoroughly
// good arrangement — has two unrelated numbering schemes, and one of them
// commonly pins the serial at a constant. Comparing across them reports the
// most resilient configuration a domain can have as a replication fault, which
// would teach operators that this rule is noise before it ever caught a real
// one.
func serialMismatch(o Origin, d Delegation) []finding.Finding {
	groups := map[string]map[uint32][]string{}
	for _, ns := range d.Nameservers {
		if !ns.HasSerial {
			continue
		}
		provider := strings.ToLower(strings.TrimSpace(ns.Provider))
		if groups[provider] == nil {
			groups[provider] = map[uint32][]string{}
		}
		groups[provider][ns.Serial] = append(groups[provider][ns.Serial], ns.Host)
	}

	providers := make([]string, 0, len(groups))
	for provider := range groups {
		providers = append(providers, provider)
	}
	sort.Strings(providers)

	var findings []finding.Finding
	for _, provider := range providers {
		serials := groups[provider]
		if len(serials) < 2 {
			continue
		}

		values := make([]string, 0, len(serials))
		for serial, hosts := range serials {
			sort.Strings(hosts)
			values = append(values, strconv.FormatUint(uint64(serial), 10)+
				" ("+strings.Join(hosts, ", ")+")")
		}
		sort.Strings(values)

		evidence := []finding.Evidence{
			finding.ComputedEvidence("ns.serials", strings.Join(values, "; ")),
		}
		if provider != "" {
			evidence = append(evidence, finding.ComputedEvidence("ns.provider", provider))
		}
		findings = append(findings, finding.New("SURF-NS-008", o.Target, evidence...))
	}
	return findings
}

// inBailiwick reports whether a nameserver's name lies within the zone it
// serves, which is what makes glue necessary: resolving it requires asking the
// very zone the delegation is meant to reach.
func inBailiwick(domain, host string) bool {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// nameserverHosts extracts the published names.
func nameserverHosts(servers []Nameserver) []string {
	hosts := make([]string, 0, len(servers))
	for _, ns := range servers {
		hosts = append(hosts, ns.Host)
	}
	return hosts
}

// hostSet lower-cases, de-duplicates and sorts hostnames so that two NS sets
// differing only in case or order compare equal. DNS names are
// case-insensitive, and a parent that returns them in a different order has
// not disagreed with anybody.
func hostSet(hosts []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
