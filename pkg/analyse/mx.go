package analyse

import (
	"sort"
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// MXHost is a published mail exchanger together with what resolution revealed
// about it. Retrieval belongs to the caller; the judgement here stays pure.
type MXHost struct {
	// Preference is the MX preference value; lower is tried first.
	Preference int
	// Host is the exchanger hostname, without a trailing dot.
	Host string
	// Resolves reports whether the host has an A or AAAA record.
	Resolves bool
	// IsCNAME reports whether the host is a CNAME alias, which RFC 2181
	// prohibits as an MX target.
	IsCNAME bool
	// Provider is the registrable domain of the exchanger's own name, used to
	// judge whether the whole mail path rests on one operator. Retrieval
	// computes it, because deriving it correctly needs the public suffix list
	// and this package is deliberately free of that sort of dependency.
	Provider string
}

// IsNull reports whether this is the null MX of RFC 7505, which declares that a
// domain accepts no mail at all.
func (m MXHost) IsNull() bool {
	return m.Preference == 0 && (m.Host == "" || m.Host == ".")
}

// MX evaluates the mail exchangers published by a domain.
//
// hasAddress reports whether the domain itself has an A or AAAA record. It
// matters because a domain with no MX but with an address record still attracts
// mail: senders fall back to the address record, so the absence of a null MX is
// only worth reporting when there is something to fall back to.
func MX(o Origin, hosts []MXHost, hasAddress bool) []finding.Finding {
	var findings []finding.Finding
	target := o.Target

	// A null MX is a complete policy statement, so none of the hygiene rules
	// below apply: there is deliberately nowhere for mail to go.
	for _, h := range hosts {
		if h.IsNull() {
			return findings
		}
	}

	if len(hosts) == 0 {
		if hasAddress {
			findings = append(findings, finding.New("SURF-MX-003", target,
				o.txtEvidence(target, "no MX records")))
		}
		return findings
	}

	for _, h := range hosts {
		ev := finding.ComputedEvidence("mx.host",
			strconv.Itoa(h.Preference)+" "+h.Host)

		if !h.Resolves {
			findings = append(findings, finding.New("SURF-MX-001", target, ev))
			// A host that does not resolve cannot also be diagnosed as a
			// CNAME; reporting both would be two findings for one defect.
			continue
		}
		if h.IsCNAME {
			findings = append(findings, finding.New("SURF-MX-002", target, ev))
		}
	}

	if len(hosts) == 1 {
		findings = append(findings, finding.New("SURF-MX-004", target,
			finding.ComputedEvidence("mx.host_count", "1"),
			finding.ComputedEvidence("mx.host", hosts[0].Host)))
	}

	findings = append(findings, mxSingleProvider(o, hosts)...)

	return findings
}

// mxSingleProvider reports a mail path that depends entirely on one operator.
//
// The provider is taken from the registrable domain of each exchanger's name,
// which is a direct observation rather than an inferred ASN: an organisation
// whose exchangers are all under one registrable domain has one mail operator,
// and an outage or compromise there stops or intercepts all of its mail. Every
// exchanger having a distinct preference makes no difference; they fail
// together.
//
// This is Low severity because a single reputable mail provider is the normal
// and usually correct arrangement. It is reported for operators whose
// availability requirements justify a second path, not as a defect.
func mxSingleProvider(o Origin, hosts []MXHost) []finding.Finding {
	if len(hosts) < 2 {
		// SURF-MX-004 already reports the single-exchanger case in full.
		return nil
	}

	providers := map[string]bool{}
	var names []string
	for _, h := range hosts {
		p := strings.ToLower(strings.TrimSpace(h.Provider))
		if p == "" {
			// An exchanger whose provider cannot be determined may be the
			// second one. Concluding "all one provider" from an incomplete set
			// would be a finding drawn from data that is missing.
			return nil
		}
		providers[p] = true
		names = append(names, h.Host)
	}

	if len(providers) != 1 {
		return nil
	}

	var provider string
	for p := range providers {
		provider = p
	}
	sort.Strings(names)

	f := finding.New("SURF-MX-005", o.Target,
		finding.ComputedEvidence("mx.provider", provider),
		finding.ComputedEvidence("mx.hosts", strings.Join(names, ", "))).
		WithBasis("The operator is inferred from the registrable domain of the " +
			"exchanger hostnames, not observed directly.")

	// Exchangers named inside the organisation's own domain say nothing about
	// who runs them: mail.example.com may be self-hosted or may be a vanity
	// name for a hosted service. The observation stands but the confidence
	// must not.
	if inBailiwick(o.Target, provider) {
		f = f.WithConfidence(finding.ConfidenceLow).
			WithDescription("Every mail exchanger is named within the organisation's own domain, " +
				"so who operates them cannot be determined from DNS. This is reported so an " +
				"operator can confirm whether the mail path has more than one operator behind it.")
	}

	return []finding.Finding{f}
}

// ParseMX turns "<preference> <host>" strings, as retrieved from DNS, into
// MXHost values. Resolution state is left unset for the caller to fill in.
func ParseMX(records []string) []MXHost {
	var hosts []MXHost
	for _, r := range records {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		pref, host, found := strings.Cut(r, " ")
		if !found {
			host, pref = pref, "0"
		}
		n, err := strconv.Atoi(strings.TrimSpace(pref))
		if err != nil {
			continue
		}
		host = strings.TrimSpace(host)
		// A bare "." is the null MX and must keep its meaning, so only a
		// trailing dot on a real hostname is removed.
		if host != "." {
			host = strings.TrimSuffix(host, ".")
		}
		hosts = append(hosts, MXHost{Preference: n, Host: host})
	}
	return hosts
}
