package audit

import (
	"context"
	"strings"

	"github.com/miekg/dns"

	d "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/scanner"
	"github.com/adedayo/vantage/pkg/takeover"
)

// maxAliasDepth bounds how far an alias chain is followed. RFC 1034 does not
// permit chains of any great length, and a bound is what stops a deliberately
// circular chain turning a check into an infinite loop.
const maxAliasDepth = 8

// fetchTakeover gathers alias chains and delegation state for the takeover
// rules.
//
// Only names the caller supplied, plus the apex, are examined. Nothing is
// guessed: probing invented names would be enumeration by brute force, which
// spec 012 forbids, and would produce findings about hosts the operator never
// published. Certificate Transparency enumeration is the sanctioned way to
// widen this set and is a separate, opt-in capability.
func fetchTakeover(ctx context.Context, c *Cache, domain string, hosts []string, corroborate bool) (analyse.TakeoverObservation, error) {
	db, err := takeover.Load()
	if err != nil {
		return analyse.TakeoverObservation{}, err
	}

	obs := analyse.TakeoverObservation{
		Domain:           strings.TrimSuffix(domain, "."),
		HTTPCorroborated: corroborate,
	}

	for _, host := range dedupeHosts(append([]string{obs.Domain}, hosts...)) {
		if h, ok := assessAlias(ctx, c, db, host); ok {
			if corroborate {
				corroborateHost(ctx, c.HTTP(), &h)
			}
			obs.Hosts = append(obs.Hosts, h)
		}
	}

	// A wildcard makes every NXDOMAIN-based conclusion in this check weaker,
	// so it is established before the findings are drawn rather than after.
	if wildcards, err := probeWildcard(ctx, c, obs.Domain); err == nil {
		obs.WildcardPresent = wildcards.HasWildcardAddress()
	}

	obs.Nameservers = danglingNameservers(ctx, c, obs.Domain)
	return obs, nil
}

// corroborate is the HTTP corroboration function, indirected so that tests can
// exercise the wiring between retrieval and judgement without depending on a
// name that resolves to a server they control.
var corroborate = scanner.CorroborateTakeover

// corroborateHost asks the host's web server whether the service considers the
// name unclaimed.
//
// Only hosts matching a fingerprint that declares claim-me body fragments are
// fetched. Requesting every alias would mean sending HTTP traffic to third
// parties for no diagnostic gain, which is exactly the sort of incidental
// noise spec 012 requires the tool to avoid.
func corroborateHost(ctx context.Context, hc d.Doer, h *analyse.TakeoverHost) {
	if h.Fingerprint == nil || len(h.Fingerprint.HTTPBody) == 0 {
		return
	}
	if h.Fingerprint.Status == takeover.StatusNotVulnerable {
		return
	}

	res := corroborate(ctx, hc, h.Host, h.Fingerprint.HTTPBody)
	h.HTTPFetched = res.Fetched
	h.HTTPUnclaimed = res.Unclaimed
	h.HTTPMatched = res.Matched
	h.HTTPURL = res.URL
}

// assessAlias follows a host's CNAME chain and establishes whether the terminal
// target exists.
func assessAlias(ctx context.Context, c *Cache, db takeover.Database, host string) (analyse.TakeoverHost, bool) {
	h := analyse.TakeoverHost{Host: host}

	name := host
	for depth := 0; depth < maxAliasDepth; depth++ {
		msg, _, err := c.Exchange(ctx, name, dns.TypeCNAME)
		if err != nil || msg == nil {
			break
		}
		var next string
		for _, rr := range msg.Answer {
			if cname, ok := rr.(*dns.CNAME); ok {
				next = strings.TrimSuffix(cname.Target, ".")
				break
			}
		}
		if next == "" || strings.EqualFold(next, name) {
			break
		}
		h.Chain = append(h.Chain, next)
		name = next
	}

	if len(h.Chain) == 0 {
		return h, false
	}
	h.CNAME = h.Chain[len(h.Chain)-1]

	if f, ok := db.Match(h.CNAME); ok {
		h.Fingerprint = &f
	}

	h.TargetResolves, h.TargetNXDOMAIN = existence(ctx, c, h.CNAME)
	return h, true
}

// existence reports whether a name resolves and whether the resolver said
// definitively that it does not exist.
//
// The two are not opposites. A name that neither resolves nor returns NXDOMAIN
// — SERVFAIL, a timeout, an empty NOERROR — has told us nothing, and every rule
// in this check treats that as "unknown" rather than "absent". Reporting a
// Critical takeover because a query failed would be the worst false positive
// this tool could produce.
//
// The converse is just as damaging and less obvious: the resolver layer reports
// NXDOMAIN as ErrNotFound with no message, so an implementation that discards
// errors sees nothing at all and stays silent on every genuinely dangling
// alias — the one condition this check exists to find.
func existence(ctx context.Context, c *Cache, name string) (resolves, nxdomain bool) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
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

// danglingNameservers reports delegated nameservers whose own names do not
// exist.
func danglingNameservers(ctx context.Context, c *Cache, domain string) []analyse.TakeoverNameserver {
	msg, _, err := c.Exchange(ctx, domain, dns.TypeNS)
	if err != nil || msg == nil {
		return nil
	}

	var servers []analyse.TakeoverNameserver
	for _, rr := range msg.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		host := strings.TrimSuffix(ns.Ns, ".")
		resolves, nxdomain := existence(ctx, c, host)
		if resolves {
			continue
		}
		servers = append(servers, analyse.TakeoverNameserver{Host: host, NXDOMAIN: nxdomain})
	}
	return servers
}

// hostsWithin returns the supplied hosts that belong to the target, so that a
// single host list can be given for a whole portfolio without names leaking
// between domains. A name from another domain is silently ignored rather than
// assessed against the wrong zone.
func hostsWithin(domain string, hosts []string) []string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	var within []string
	for _, h := range hosts {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if name == domain || strings.HasSuffix(name, "."+domain) {
			within = append(within, name)
		}
	}
	return within
}

// dedupeHosts normalises and de-duplicates the host list.
func dedupeHosts(hosts []string) []string {
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
	return out
}

// takeoverRecords renders the alias chains examined, so a reader sees what was
// assessed rather than only what was wrong.
func takeoverRecords(obs analyse.TakeoverObservation) []string {
	records := make([]string, 0, len(obs.Hosts))
	for _, h := range obs.Hosts {
		line := h.Host + " CNAME " + strings.Join(h.Chain, " -> ")
		switch {
		case h.TargetResolves:
			line += " (target resolves)"
		case h.TargetNXDOMAIN:
			line += " (target NXDOMAIN)"
		default:
			line += " (target state unknown)"
		}
		if h.Fingerprint != nil {
			line += " [" + h.Fingerprint.Service + "]"
		}
		switch {
		case h.HTTPUnclaimed:
			line += " [HTTP: unclaimed]"
		case h.HTTPFetched:
			line += " [HTTP: in use]"
		}
		records = append(records, line)
	}
	return records
}
