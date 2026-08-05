package audit

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/ct"
)

// ctSource is the log service used, indirected so that tests can substitute
// one. It is nil in normal operation, in which case the sources are built per
// run from the cache's HTTP egress — a package-level default would reach past
// the boundary an embedding consumer controls.
var ctSource ct.Source

// sourceFor returns the CT sources for a run, preferring a substituted source.
func sourceFor(c *Cache) ct.Source {
	if ctSource != nil {
		return ctSource
	}
	return ct.DefaultSourcesWith(c.HTTP())
}

// maxCTHosts bounds how many discovered names are resolved.
//
// A large organisation's certificate history can run to thousands of names.
// Resolving all of them would turn one audit into a sustained burst of queries
// against the target's nameservers, which is precisely the behaviour spec 012
// requires this tool to avoid. The bound is applied after sorting, so the set
// assessed is deterministic rather than whatever the log returned first.
const maxCTHosts = 200

// enumerateCT discovers names from Certificate Transparency and establishes
// whether each still resolves.
func enumerateCT(ctx context.Context, c *Cache, domain string) (analyse.CTObservation, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	result, err := ct.Enumerate(ctx, sourceFor(c), domain)
	if err != nil {
		return analyse.CTObservation{}, err
	}

	obs := analyse.CTObservation{
		Domain:           domain,
		Source:           result.Source,
		WildcardNames:    result.WildcardNames,
		CertificateCount: len(result.Certificates),
	}

	latest := latestExpiry(result.Certificates)

	hosts := result.Hosts
	if len(hosts) > maxCTHosts {
		hosts = hosts[:maxCTHosts]
	}

	for _, name := range hosts {
		h := analyse.CTHost{Host: name}
		if e, ok := latest[name]; ok {
			h.Issuer = e.issuer
			if !e.notAfter.IsZero() {
				h.Expiry = e.notAfter.Format("2006-01-02")
			}
		}
		h.Resolves, h.NXDOMAIN = ctExistence(ctx, c, name)
		obs.Hosts = append(obs.Hosts, h)
	}

	return obs, nil
}

type certSummary struct {
	issuer   string
	notAfter time.Time
}

// latestExpiry records, for each name, the most recently expiring certificate.
// An old certificate for a name that has since been re-issued would otherwise
// be reported as the evidence, understating how current the exposure is.
func latestExpiry(certs []ct.Certificate) map[string]certSummary {
	latest := map[string]certSummary{}
	for _, cert := range certs {
		for _, name := range cert.Names {
			if existing, ok := latest[name]; ok && !cert.NotAfter.After(existing.notAfter) {
				continue
			}
			latest[name] = certSummary{issuer: cert.Issuer, notAfter: cert.NotAfter}
		}
	}
	return latest
}

// ctExistence reports whether a name resolves and whether the resolver said
// definitively that it does not exist.
//
// A name may exist without an address — a CNAME or a delegation — so all three
// are asked before concluding it is gone. Reporting a live subdomain as an
// abandoned certificate would be a false positive on a rule whose entire value
// is that it is worth reading.
func ctExistence(ctx context.Context, c *Cache, name string) (resolves, nxdomain bool) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS} {
		msg, _, err := c.Exchange(ctx, name, qtype)
		if err != nil {
			if isAbsent(err) {
				nxdomain = true
			}
			continue
		}
		if msg == nil {
			continue
		}
		if len(msg.Answer) > 0 {
			return true, false
		}
		if msg.Rcode == dns.RcodeNameError {
			nxdomain = true
		}
	}
	return false, nxdomain
}
