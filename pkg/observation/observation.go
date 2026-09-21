// Package observation holds the structured data checks gather, in a form a
// consumer can read without parsing rendered prose.
//
// It is a leaf: it imports netattr and nothing else in this module. That is
// deliberate. The judgement types in pkg/analyse produce finding.Finding, so
// analyse imports finding, and finding therefore cannot import analyse. Facts
// and judgements belong on opposite sides of that line anyway — what was
// observed does not depend on what any rule concludes about it.
//
// Rendered records remain the presentation surface. These types are the
// contract. A consumer reading prose gets no match when the prose is reworded,
// which reads as "nothing observed" rather than as an error — silence in the
// reassuring direction, which is the failure mode worth designing out.
package observation

import (
	"time"

	"github.com/adedayo/vantage/pkg/netattr"
)

// NetworkHost is one resolved name and what its addresses could be attributed
// to.
type NetworkHost struct {
	// Host is the name.
	Host string `json:"host"`
	// Role describes why the name was assessed — "apex", "host", "mail
	// exchanger" or "nameserver" — so a reader can tell an exposure on a web
	// host from one on mail infrastructure.
	Role string `json:"role"`
	// Attributions is one entry per address the name resolves to.
	Attributions []netattr.Attribution `json:"attributions,omitempty"`
}

// Network is everything retrieval gathered for the attribution rules.
type Network struct {
	// Domain is the zone assessed.
	Domain string `json:"domain"`
	// Hosts are the names examined.
	Hosts []NetworkHost `json:"hosts,omitempty"`
	// Estate is the set of providers the domain's own apex and mail
	// infrastructure sit in. It is derived rather than declared, so the check
	// needs no configuration to have an opinion about what "outside the
	// estate" means.
	Estate map[string]bool `json:"estate,omitempty"`
	// ExpectedJurisdictions are the ISO 3166-1 alpha-2 countries the operator
	// declared their infrastructure should be in. Empty means no expectation
	// was stated, and the jurisdiction rule is then not evaluated at all.
	ExpectedJurisdictions []string `json:"expected_jurisdictions,omitempty"`
	// FailedSources names the provider range publications that could not be
	// loaded.
	//
	// Coverage gaps produce false negatives, not false positives: if a
	// provider's ranges are unavailable, every address of theirs reads as
	// "unattributed" and the result is indistinguishable from a domain that
	// genuinely uses no third-party hosting. A consumer must be able to say
	// "we could not look" rather than "there is nothing there".
	FailedSources []string `json:"failed_sources,omitempty"`
	// StaleSources names publications served from a cache entry older than
	// its lifetime, because the endpoint could not be reached. The
	// attributions remain usable — a prefix that moved last week is almost
	// always still announced by the same operator — but a reader comparing two
	// runs deserves to know the basis was not refreshed.
	StaleSources []string `json:"stale_sources,omitempty"`
	// Provenance records where each provider's ranges came from and when.
	Provenance []netattr.SourceProvenance `json:"provenance,omitempty"`
}

// CTHost is one name disclosed by Certificate Transparency.
type CTHost struct {
	// Host is the name.
	Host string `json:"host"`
	// Resolves reports whether the name has an address, an alias or a
	// delegation.
	Resolves bool `json:"resolves"`
	// NXDOMAIN reports that the resolver answered definitively that the name
	// does not exist.
	//
	// It is not the negation of Resolves: a query that failed leaves both
	// false, and nothing may be concluded from that. A consumer feeding
	// discovery must not collapse the three states into two.
	NXDOMAIN bool `json:"nxdomain"`
	// Issuer is the certificate authority that certified the name.
	Issuer string `json:"issuer,omitempty"`
	// Expiry is when the most recent certificate for the name expires.
	Expiry string `json:"expiry,omitempty"`
}

// Undetermined reports that the name's existence could not be established:
// the query neither resolved nor returned a definitive absence.
//
// Provided so that consumers need not rediscover that !Resolves does not mean
// absent. A discovery pipeline that treats an undetermined name as absent
// drops real assets; one that treats it as present invents them.
func (h CTHost) Undetermined() bool { return !h.Resolves && !h.NXDOMAIN }

// CT is everything Certificate Transparency enumeration found.
type CT struct {
	// Domain is the zone assessed.
	Domain string `json:"domain"`
	// Source names the log service the data came from.
	Source string `json:"source,omitempty"`
	// Hosts are the discovered names and their resolution state.
	Hosts []CTHost `json:"hosts,omitempty"`
	// WildcardNames are wildcard identities covering the domain.
	WildcardNames []string `json:"wildcard_names,omitempty"`
	// CertificateCount is how many issuances were examined.
	CertificateCount int `json:"certificate_count"`
	// Discovered is how many distinct in-domain names the logs held, before
	// any bound on how many were resolved. It differs from len(Hosts) only
	// when the bound applied.
	Discovered int `json:"discovered"`
}

// ServiceState describes what a declared service probe established.
type ServiceState string

const (
	ServiceResponding    ServiceState = "responding"
	ServiceNotResponding ServiceState = "not_responding"
	ServiceUnknown       ServiceState = "unknown"
)

// ServiceLayer is the protocol layer a probe was asked to assess.
type ServiceLayer string

const (
	ServiceLayerTCP      ServiceLayer = "tcp"
	ServiceLayerTLS      ServiceLayer = "tls"
	ServiceLayerHTTP     ServiceLayer = "http"
	ServiceLayerStartTLS ServiceLayer = "starttls"
)

// ServiceEvidence contains bounded facts gathered by a service probe. Empty
// fields mean that the requested probe did not establish that fact.
type ServiceEvidence struct {
	Address            string `json:"address,omitempty"`
	ResponseClass      string `json:"response_class,omitempty"`
	TLSVersion         string `json:"tls_version,omitempty"`
	CipherSuite        string `json:"cipher_suite,omitempty"`
	CertificateSubject string `json:"certificate_subject,omitempty"`
	CertificateIssuer  string `json:"certificate_issuer,omitempty"`
	CertificateExpiry  string `json:"certificate_expiry,omitempty"`
	SNI                string `json:"sni,omitempty"`
	HTTPStatus         int    `json:"http_status,omitempty"`
	HSTS               string `json:"hsts,omitempty"`
	Location           string `json:"location,omitempty"`
	Server             string `json:"server,omitempty"`
	Error              string `json:"error,omitempty"`
}

// ServiceObservation is the structured result of one declared service probe.
// A lower-layer response does not imply that a higher-layer probe responded.
type ServiceObservation struct {
	Host         string          `json:"host"`
	Port         uint16          `json:"port"`
	Transport    string          `json:"transport"`
	Protocol     string          `json:"protocol"`
	Service      string          `json:"service,omitempty"`
	Layer        ServiceLayer    `json:"layer"`
	State        ServiceState    `json:"state"`
	Evidence     ServiceEvidence `json:"evidence"`
	ObservedAt   time.Time       `json:"observed_at"`
	ProbeProfile string          `json:"probe_profile"`
}

// SameBasis reports whether two sets of provenance describe the same data,
// disregarding when it was fetched.
//
// Attribution is derived from data this tool fetches, so it can change without
// the audited domain changing at all. A consumer diffing two runs needs to
// tell "the host moved" from "our data was refreshed", and the fetch time
// changes on every refresh by definition. Comparing on it would report drift
// on every run, which destroys trust in the signal faster than missing drift
// does.
//
// This lives here rather than in each consumer because the judgement is the
// library's to make: it knows which fields are material to an attribution and
// which merely record how the data arrived.
func SameBasis(a, b []netattr.SourceProvenance) bool {
	if len(a) != len(b) {
		return false
	}
	index := make(map[string]string, len(a))
	for _, p := range a {
		index[p.Provider] = p.URL
	}
	for _, p := range b {
		url, ok := index[p.Provider]
		if !ok || url != p.URL {
			return false
		}
	}
	return true
}

// Age reports how old the oldest provenance entry is at the given time, and
// whether any provenance was recorded at all.
//
// Offered so a consumer can decide for itself whether an attribution is too
// stale to act on, rather than having a threshold chosen for it here.
func Age(p []netattr.SourceProvenance, now time.Time) (time.Duration, bool) {
	if len(p) == 0 {
		return 0, false
	}
	oldest := p[0].Fetched
	for _, e := range p[1:] {
		if e.Fetched.Before(oldest) {
			oldest = e.Fetched
		}
	}
	return now.Sub(oldest), true
}
