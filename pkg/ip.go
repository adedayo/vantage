package vantage

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

// LookupIP resolves a host name to its A and AAAA addresses using the same
// platform-independent resolver configuration as the rest of the package,
// rather than relying on the operating system resolver. This keeps behaviour
// consistent across Linux, macOS and Windows and honours the --resolver flag.
//
// If the host is already an IP literal it is returned as-is.
func LookupIP(ctx context.Context, r Resolver, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	var ips []net.IP
	var firstErr error

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, _, err := r.ExchangeFrom(ctx, host, qtype)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A)
			case *dns.AAAA:
				ips = append(ips, v.AAAA)
			}
		}
	}

	if len(ips) > 0 {
		return ips, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, ErrNotFound
}
