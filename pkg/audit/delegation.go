package audit

import (
	"context"
	"strings"

	"github.com/miekg/dns"

	"github.com/adedayo/vantage/pkg/analyse"
)

// recursionProbe is the name used to test whether an authoritative server will
// resolve on behalf of a stranger.
//
// It must be a name no authoritative server for the target could legitimately
// answer from its own data, and one that reliably exists so that a refusal is
// distinguishable from an NXDOMAIN. A root server's own name satisfies both and
// is answered by every functioning recursive resolver.
const recursionProbe = "a.root-servers.net."

// fetchDelegation gathers everything the delegation rules need: the zone's own
// NS set, the parent's view of it, and the behaviour of each server when
// queried directly.
//
// Direct queries to the target's nameservers are what this check is for, and
// they are why spec 012 requires the authorisation statement in the README.
// They remain observations: a question is asked, and the answer is recorded.
func fetchDelegation(ctx context.Context, c *Cache, domain string) (analyse.Delegation, error) {
	del := analyse.Delegation{
		Domain: strings.TrimSuffix(domain, "."),
		Glue:   map[string][]string{},
	}

	msg, _, err := c.Exchange(ctx, del.Domain, dns.TypeNS)
	if err != nil && !isAbsent(err) {
		return del, err
	}
	if msg != nil {
		for _, rr := range msg.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				del.Nameservers = append(del.Nameservers,
					analyse.Nameserver{Host: strings.TrimSuffix(ns.Ns, ".")})
			}
		}
	}
	if len(del.Nameservers) == 0 {
		return del, nil
	}

	fetchParentDelegation(ctx, c, &del)

	for i := range del.Nameservers {
		interrogate(ctx, c, del.Domain, &del.Nameservers[i])
	}
	return del, nil
}

// fetchParentDelegation asks a parent nameserver for its referral, which is the
// only place the delegated NS set and the glue records can be observed.
//
// Failure is silent by design: analyse.Delegation records ParentChecked
// separately, so a parent that could not be consulted yields no parent-derived
// findings rather than findings drawn from an empty answer.
func fetchParentDelegation(ctx context.Context, c *Cache, del *analyse.Delegation) {
	parent := parentZone(del.Domain)
	if parent == "" {
		return
	}

	msg, _, err := c.Exchange(ctx, parent, dns.TypeNS)
	if err != nil || msg == nil {
		return
	}

	for _, rr := range msg.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		addrs := resolveHost(ctx, c, strings.TrimSuffix(ns.Ns, "."))
		if len(addrs) == 0 {
			continue
		}

		referral, err := c.Resolver().ExchangeWithServer(ctx, addrs[0], del.Domain, dns.TypeNS)
		if err != nil || referral == nil {
			continue
		}

		// A parent server returns the delegation in the authority section. The
		// answer section is also read, because a server that is authoritative
		// for both zones — which happens with in-house delegation — answers
		// directly instead of referring.
		for _, rr := range append(referral.Ns, referral.Answer...) {
			if child, ok := rr.(*dns.NS); ok &&
				strings.EqualFold(strings.TrimSuffix(child.Hdr.Name, "."), del.Domain) {
				del.ParentNS = append(del.ParentNS, strings.TrimSuffix(child.Ns, "."))
			}
		}
		for _, rr := range referral.Extra {
			switch g := rr.(type) {
			case *dns.A:
				addGlue(del, g.Hdr.Name, g.A.String())
			case *dns.AAAA:
				addGlue(del, g.Hdr.Name, g.AAAA.String())
			}
		}

		del.ParentChecked = true
		return
	}
}

func addGlue(del *analyse.Delegation, name, address string) {
	key := strings.ToLower(strings.TrimSuffix(name, "."))
	del.Glue[key] = append(del.Glue[key], address)
}

// interrogate queries one nameserver directly to establish whether it is
// authoritative for the zone, which serial it serves, and whether it recurses
// for strangers.
func interrogate(ctx context.Context, c *Cache, domain string, ns *analyse.Nameserver) {
	ns.Provider = organisationalDomain(ns.Host)
	ns.Addresses = resolveHost(ctx, c, ns.Host)
	if len(ns.Addresses) == 0 {
		// Unresolvable is left as "did not answer": SURF-NS-005 reports it at
		// reduced confidence, which is the honest reading of a server we could
		// not reach rather than one we proved to be lame.
		return
	}

	addr := ns.Addresses[0]

	if soa, err := c.Resolver().ExchangeWithServer(ctx, addr, domain, dns.TypeSOA); err == nil && soa != nil {
		ns.Answered = true
		ns.Authoritative = soa.Authoritative && soa.Rcode == dns.RcodeSuccess
		for _, rr := range soa.Answer {
			if record, ok := rr.(*dns.SOA); ok {
				ns.Serial, ns.HasSerial = record.Serial, true
			}
		}
	}

	probe, err := c.Resolver().ExchangeWithServer(ctx, addr, recursionProbe, dns.TypeA)
	if err != nil || probe == nil {
		return
	}
	ns.RecursionTested = true
	// Recursion is asserted only on a complete answer. RecursionAvailable
	// alone is advertised by servers that then refuse, and refusing is the
	// correct behaviour being claimed rather than a defect to report.
	ns.OpenRecursive = probe.RecursionAvailable &&
		probe.Rcode == dns.RcodeSuccess && len(probe.Answer) > 0
}

// resolveHost returns a host's addresses through the run cache.
func resolveHost(ctx context.Context, c *Cache, host string) []string {
	var addresses []string
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg, _, err := c.Exchange(ctx, host, qtype)
		if err != nil || msg == nil {
			continue
		}
		for _, rr := range msg.Answer {
			switch r := rr.(type) {
			case *dns.A:
				addresses = append(addresses, r.A.String())
			case *dns.AAAA:
				addresses = append(addresses, r.AAAA.String())
			}
		}
	}
	return addresses
}

// parentZone returns the name one label above the domain, or "" at the root.
func parentZone(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	_, rest, found := strings.Cut(domain, ".")
	if !found || rest == "" {
		return ""
	}
	return rest
}

// delegationRecords renders the delegation for the Records field, so a reader
// sees the NS set and each server's behaviour rather than only the verdict.
func delegationRecords(del analyse.Delegation) []string {
	records := make([]string, 0, len(del.Nameservers))
	for _, ns := range del.Nameservers {
		line := ns.Host
		if len(ns.Addresses) > 0 {
			line += " (" + strings.Join(ns.Addresses, ", ") + ")"
		}
		switch {
		case ns.Authoritative:
			line += " authoritative"
		case ns.Answered:
			line += " answered, not authoritative"
		default:
			line += " no response"
		}
		records = append(records, line)
	}
	return records
}
