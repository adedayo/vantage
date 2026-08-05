// Package scanner provides the high-level DNS security auditing API used by the
// vantage CLI. All functions take a context.Context as their first argument and
// return errors prefixed with "error:".
//
// Resolver configuration is platform independent: see resolver.go in the
// vantage package for the discovery order (explicit override, the
// VANTAGE_RESOLVERS environment variable, platform-native configuration, then
// well-known public resolvers).
package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	d "github.com/adedayo/vantage/pkg"
)

// formatTLSA renders TLSA answers as "usage selector matchingType CERTHEX".
func formatTLSA(answers []dns.RR) (string, error) {
	var records []string
	for _, rr := range answers {
		if tlsa, ok := rr.(*dns.TLSA); ok {
			records = append(records, fmt.Sprintf("%d %d %d %s",
				tlsa.Usage, tlsa.Selector, tlsa.MatchingType,
				strings.ToUpper(tlsa.Certificate)))
		}
	}
	if len(records) == 0 {
		return "", fmt.Errorf("error: not found")
	}
	return strings.Join(records, ", "), nil
}

// formatCAA renders CAA answers as "flag tag value".
func formatCAA(answers []dns.RR) ([]string, error) {
	var records []string
	for _, rr := range answers {
		if caa, ok := rr.(*dns.CAA); ok {
			records = append(records, fmt.Sprintf("%d %s %s", caa.Flag, caa.Tag, caa.Value))
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("error: not found")
	}
	return records, nil
}

// parseDMARCPolicy extracts the normalised p= tag from DMARC TXT records.
func parseDMARCPolicy(txts []string) (string, error) {
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if !strings.HasPrefix(txt, "v=DMARC1") {
			continue
		}
		for _, p := range strings.Split(txt, ";") {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "p=") {
				return strings.ToLower(strings.TrimPrefix(p, "p=")), nil
			}
		}
	}
	return "", fmt.Errorf("error: not found")
}

// parseDMARCReporting extracts the rua and ruf URIs from DMARC TXT records.
func parseDMARCReporting(txts []string) (rua, ruf []string, err error) {
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if !strings.HasPrefix(txt, "v=DMARC1") {
			continue
		}
		for _, p := range strings.Split(txt, ";") {
			p = strings.TrimSpace(p)
			switch {
			case strings.HasPrefix(p, "rua="):
				rua = append(rua, strings.TrimPrefix(p, "rua="))
			case strings.HasPrefix(p, "ruf="):
				ruf = append(ruf, strings.TrimPrefix(p, "ruf="))
			}
		}
	}
	if len(rua) == 0 && len(ruf) == 0 {
		return nil, nil, fmt.Errorf("error: not found")
	}
	return rua, ruf, nil
}

// firstIPv4 returns the first IPv4 address in the slice, or nil.
func firstIPv4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	}
	return nil
}

// dnsblQueryName builds the reversed-octet DNSBL query name for an IPv4 address.
func dnsblQueryName(ip4 net.IP, blocklist string) string {
	return fmt.Sprintf("%d.%d.%d.%d.%s", ip4[3], ip4[2], ip4[1], ip4[0], blocklist)
}

// LookupSPF retrieves the SPF record for a domain and returns the raw record string.
func LookupSPF(ctx context.Context, r d.Resolver, domain string) (string, error) {
	txts, err := d.LookupTXT(ctx, r, domain)
	if err != nil {
		return "", err
	}
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(txt, "v=spf1") {
			return txt, nil
		}
	}
	return "", fmt.Errorf("error: not found")
}

// LookupDKIM retrieves the DKIM TXT record for a domain and selector.
func LookupDKIM(ctx context.Context, r d.Resolver, domain, selector string) (string, error) {
	txts, err := d.LookupTXT(ctx, r, fmt.Sprintf("%s._domainkey.%s", selector, domain))
	if err != nil {
		return "", err
	}
	if len(txts) > 0 {
		return txts[0], nil
	}
	return "", fmt.Errorf("error: not found")
}

// LookupDMARC parses the DMARC record and returns the effective policy
// (reject, quarantine, none). Unrecognised policy values are returned verbatim.
func LookupDMARC(ctx context.Context, r d.Resolver, domain string) (string, error) {
	txts, err := d.LookupTXT(ctx, r, "_dmarc."+domain)
	if err != nil {
		return "", err
	}
	return parseDMARCPolicy(txts)
}

// ParseDMARCReporting extracts the rua and ruf URIs from the DMARC record.
func ParseDMARCReporting(ctx context.Context, r d.Resolver, domain string) (rua []string, ruf []string, err error) {
	txts, err := d.LookupTXT(ctx, r, "_dmarc."+domain)
	if err != nil {
		return nil, nil, err
	}
	return parseDMARCReporting(txts)
}

// CheckMTASts returns the raw MTA-STS TXT record if present.
func CheckMTASts(ctx context.Context, r d.Resolver, domain string) (string, error) {
	txts, err := d.LookupTXT(ctx, r, "_mta-sts."+domain)
	if err != nil {
		return "", err
	}
	if len(txts) > 0 {
		return txts[0], nil
	}
	return "", fmt.Errorf("error: not found")
}

// CheckDNSSEC queries DNSKEY records and returns "enabled" if any are present,
// otherwise the value "not found" (a value, not an error).
func CheckDNSSEC(ctx context.Context, r d.Resolver, domain string) (string, error) {
	resp, _, err := r.ExchangeFrom(ctx, domain, dns.TypeDNSKEY)
	if err != nil {
		return "", err
	}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.DNSKEY); ok {
			return "enabled", nil
		}
	}
	return "not found", nil
}

// lookupTLSA queries TLSA records for an arbitrary name.
func lookupTLSA(ctx context.Context, r d.Resolver, name string) (string, error) {
	resp, _, err := r.ExchangeFrom(ctx, name, dns.TypeTLSA)
	if err != nil {
		return "", err
	}
	return formatTLSA(resp.Answer)
}

// CheckDANE retrieves TLSA records for the SMTP service (_25._tcp).
func CheckDANE(ctx context.Context, r d.Resolver, domain string) (string, error) {
	return lookupTLSA(ctx, r, "_25._tcp."+domain)
}

// LookupTLASSMTP is an alias for CheckDANE (SMTP TLSA records).
func LookupTLASSMTP(ctx context.Context, r d.Resolver, domain string) (string, error) {
	return CheckDANE(ctx, r, domain)
}

// LookupTLSAHTTPS retrieves TLSA records for the HTTPS service (_443._tcp).
func LookupTLSAHTTPS(ctx context.Context, r d.Resolver, domain string) (string, error) {
	return lookupTLSA(ctx, r, "_443._tcp."+domain)
}

// LookupTLSASSH retrieves TLSA records for the SSH service (_22._tcp).
func LookupTLSASSH(ctx context.Context, r d.Resolver, domain string) (string, error) {
	return lookupTLSA(ctx, r, "_22._tcp."+domain)
}

// LookupCAA retrieves CAA records for a domain as formatted strings.
func LookupCAA(ctx context.Context, r d.Resolver, domain string) ([]string, error) {
	resp, _, err := r.ExchangeFrom(ctx, domain, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	return formatCAA(resp.Answer)
}

// ReverseLookupPTR resolves the domain to IP addresses, then performs a PTR
// lookup for the first address.
func ReverseLookupPTR(ctx context.Context, r d.Resolver, domain string) (string, error) {
	ips, err := d.LookupIP(ctx, r, domain)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("error: no IPs found")
	}
	ptrName, err := dns.ReverseAddr(ips[0].String())
	if err != nil {
		return "", fmt.Errorf("error: unable to construct PTR name: %w", err)
	}
	resp, _, err := r.ExchangeFrom(ctx, ptrName, dns.TypePTR)
	if err != nil {
		return "", err
	}
	for _, rr := range resp.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			return ptr.Ptr, nil
		}
	}
	return "", fmt.Errorf("error: not found")
}

// VerifyNSSEC checks for the presence of NSEC or NSEC3 records in the zone.
func VerifyNSSEC(ctx context.Context, r d.Resolver, domain string) (bool, error) {
	for _, qtype := range []uint16{dns.TypeNSEC, dns.TypeNSEC3} {
		resp, _, err := r.ExchangeRawFrom(ctx, domain, qtype)
		if err == nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// CheckDNSBL queries a DNSBL for the domain's first IPv4 address. A non-success
// response code (e.g. NXDOMAIN) means "not listed" and is not an error.
func CheckDNSBL(ctx context.Context, r d.Resolver, domain, blocklist string) (bool, error) {
	ips, err := d.LookupIP(ctx, r, domain)
	if err != nil {
		return false, err
	}
	if len(ips) == 0 {
		return false, fmt.Errorf("error: no IPs found for domain")
	}
	ip4 := firstIPv4(ips)
	if ip4 == nil {
		return false, fmt.Errorf("error: no IPv4 address for DNSBL check")
	}
	resp, _, err := r.ExchangeRawFrom(ctx, dnsblQueryName(ip4, blocklist), dns.TypeA)
	if err != nil {
		return false, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false, nil // not listed
	}
	return len(resp.Answer) > 0, nil
}

// ValidatePublicSuffix reports whether the given domain equals its own public
// suffix (i.e. it is a TLD/eTLD). No DNS query is performed.
func ValidatePublicSuffix(_ context.Context, subdomain string) (bool, error) {
	ps, _ := publicsuffix.PublicSuffix(subdomain)
	return ps == subdomain, nil
}
