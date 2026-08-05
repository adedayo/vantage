package scanner

import (
	"context"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	d "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
)

// DMARCResolver adapts the package's live lookups to the interface the DMARC
// evaluator expects, for organisational-domain fallback and external
// destination verification.
type DMARCResolver struct{}

// TXT returns the TXT records published at a name.
func (DMARCResolver) TXT(ctx context.Context, name string) ([]string, error) {
	return SPFResolver{}.TXT(ctx, name)
}

// OrganisationalDomain returns the registrable domain for a name — the domain
// whose DMARC policy a subdomain inherits.
func OrganisationalDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	suffix, _ := publicsuffix.PublicSuffix(domain)
	return analyse.OrganisationalDomain(domain, suffix)
}

// SPFResolver adapts the package's live lookups to the interface the SPF
// evaluator expects, so recursive evaluation can be driven from the CLI.
//
// The evaluator is deliberately given an interface rather than calling this
// package directly: the security judgement stays testable against synthetic
// include graphs, which is the only practical way to cover loops and the
// boundary either side of the ten-lookup limit.
type SPFResolver struct {
	// Resolver is the DNS egress this evaluator uses. It is a field rather
	// than ambient state so that a recursive SPF expansion — which follows
	// includes to names the operator never wrote down — is bounded by the
	// same egress policy as everything else.
	Resolver d.Resolver
}

// TXT returns the TXT records published at a name.
func (s SPFResolver) TXT(ctx context.Context, name string) ([]string, error) {
	msg, _, err := s.Resolver.ExchangeFrom(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var records []string
	for _, rr := range msg.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			// Long records arrive split into 255-byte strings, which must be
			// rejoined before they can be parsed as a single policy.
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}
	return records, nil
}

// HasRecords reports whether a name has records of the given kind, to
// distinguish a void lookup from a resolvable one.
//
// A lookup failure reports false rather than an error: the evaluator uses this
// only to count void lookups, and a receiver would treat an unanswered query
// the same way.
func (s SPFResolver) HasRecords(ctx context.Context, name, kind string) (bool, error) {
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	switch kind {
	case "mx":
		qtypes = []uint16{dns.TypeMX}
	case "ptr":
		qtypes = []uint16{dns.TypePTR}
	case "txt":
		qtypes = []uint16{dns.TypeTXT}
	}

	for _, qtype := range qtypes {
		msg, _, err := s.Resolver.ExchangeFrom(ctx, name, qtype)
		if err != nil {
			continue
		}
		if len(msg.Answer) > 0 {
			return true, nil
		}
	}
	return false, nil
}
