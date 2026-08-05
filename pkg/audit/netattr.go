package audit

import (
	"context"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/netattr"
)

// fetchNetworkAttribution resolves the domain's own infrastructure and any
// supplied hosts, and attributes each address to a network.
//
// The estate is derived from the apex and the mail exchangers rather than
// declared by the operator. A domain's own front door and mail path are the
// providers it has evidently chosen, so a host somewhere else is worth
// remarking on without anybody having to configure a list — and a check that
// needs configuration to say anything is a check most people never enable.
func fetchNetworkAttribution(
	ctx context.Context, c *Cache, domain string, hosts, expect []string, noNetwork bool,
) (analyse.NetworkObservation, error) {
	// With egress disabled the provider ranges cannot be fetched, but the
	// special-purpose registries are embedded, so the rule that matters most —
	// a public name resolving into internal address space — still runs. An
	// empty set attributes nothing to a provider, and the judgement treats an
	// unattributed address as unknown rather than as absent from any cloud.
	var set netattr.Set
	if !noNetwork {
		loaded, err := c.Ranges().Load(ctx)
		if err != nil {
			return analyse.NetworkObservation{}, err
		}
		set = loaded
	}

	domain = strings.TrimSuffix(domain, ".")
	obs := analyse.NetworkObservation{
		Domain:                domain,
		Estate:                map[string]bool{},
		ExpectedJurisdictions: expect,
		FailedSources:         set.Failed,
		StaleSources:          set.Stale,
		Provenance:            provenanceLines(set),
	}

	// The apex and the mail exchangers define the estate, so they are resolved
	// first and their providers recorded before anything is judged against it.
	for _, h := range estateHosts(ctx, c, domain) {
		host := attributeHost(ctx, c, set, h.name, h.role)
		if len(host.Attributions) == 0 {
			continue
		}
		for _, a := range host.Attributions {
			if a.Provider != "" {
				obs.Estate[a.Provider] = true
			}
		}
		obs.Hosts = append(obs.Hosts, host)
	}

	for _, name := range dedupeHosts(hosts) {
		if name == domain {
			continue // already assessed as the apex
		}
		if host := attributeHost(ctx, c, set, name, "host"); len(host.Attributions) > 0 {
			obs.Hosts = append(obs.Hosts, host)
		}
	}

	return obs, nil
}

type estateHost struct{ name, role string }

// provenanceLines renders where each provider's ranges came from and when.
//
// The date is rendered to the day rather than the second. Attribution is
// compared between runs by spec 013, and a timestamp that changes on every
// refresh would register as drift on every run, which is the false drift that
// specification requires be avoidable.
func provenanceLines(set netattr.Set) []string {
	lines := make([]string, 0, len(set.Provenance))
	for _, p := range set.Provenance {
		lines = append(lines, p.Provider+" ranges from "+p.URL+
			" fetched "+p.Fetched.Format("2006-01-02"))
	}
	return lines
}

// estateHosts lists the names that constitute the domain's own infrastructure.
func estateHosts(ctx context.Context, c *Cache, domain string) []estateHost {
	hosts := []estateHost{{domain, "apex"}}

	if msg, _, err := c.Exchange(ctx, domain, dns.TypeMX); err == nil && msg != nil {
		for _, rr := range msg.Answer {
			mx, ok := rr.(*dns.MX)
			if !ok || mx.Mx == "." || mx.Mx == "" {
				continue
			}
			hosts = append(hosts, estateHost{strings.TrimSuffix(mx.Mx, "."), "mail exchanger"})
		}
	}

	if msg, _, err := c.Exchange(ctx, domain, dns.TypeNS); err == nil && msg != nil {
		for _, rr := range msg.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				hosts = append(hosts, estateHost{strings.TrimSuffix(ns.Ns, "."), "nameserver"})
			}
		}
	}

	return hosts
}

// attributeHost resolves one name and attributes every address it returns.
//
// A lookup that fails contributes no attributions rather than an empty set. The
// difference matters: an empty set of addresses reads as "this name resolves
// nowhere", which is a claim, whereas a failed query supports no claim at all.
func attributeHost(
	ctx context.Context, c *Cache, set netattr.Set, name, role string,
) analyse.NetworkHost {
	host := analyse.NetworkHost{Host: name, Role: role}

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg, _, err := c.Exchange(ctx, name, qtype)
		if err != nil || msg == nil {
			continue
		}
		for _, rr := range msg.Answer {
			var ip string
			switch r := rr.(type) {
			case *dns.A:
				ip = r.A.String()
			case *dns.AAAA:
				ip = r.AAAA.String()
			default:
				continue
			}
			addr, parseErr := netip.ParseAddr(ip)
			if parseErr != nil {
				continue
			}
			host.Attributions = append(host.Attributions, set.Lookup(addr))
		}
	}

	return host
}
