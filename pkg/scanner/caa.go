package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	d "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
)

// ClimbCAA performs the RFC 8659 §3 tree-climbing search for a CAA policy,
// returning the first policy found and the label that supplied it.
//
// The climb stops below the public suffix: issuance policy is not inherited
// from a registry, so continuing would attribute someone else's policy to this
// domain.
func ClimbCAA(ctx context.Context, r d.Resolver, domain string) (analyse.CAAPolicy, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	suffix, _ := publicsuffix.PublicSuffix(domain)

	for _, name := range analyse.CAAAncestors(domain, suffix) {
		resp, _, err := r.ExchangeFrom(ctx, name, dns.TypeCAA)
		if err != nil {
			continue
		}

		var records []string
		for _, rr := range resp.Answer {
			if caa, ok := rr.(*dns.CAA); ok {
				records = append(records, fmt.Sprintf("%d %s %q", caa.Flag, caa.Tag, caa.Value))
			}
		}
		if len(records) == 0 {
			continue
		}

		return analyse.CAAPolicy{
			Records:   analyse.ParseCAA(records),
			Source:    name,
			Inherited: !strings.EqualFold(name, domain),
		}, nil
	}

	return analyse.CAAPolicy{}, nil
}
