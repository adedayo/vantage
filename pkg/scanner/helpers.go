package scanner

// helpers.go exposes server-parameterised variants of the scanner functions.
// They accept an explicit resolver address (e.g. "127.0.0.1:5353") and are used
// by scanner_test.go to run against a local mock DNS server, as well as for
// targeted diagnostics against a specific nameserver.
//
// These helpers are not part of the stable public API and may change.

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	d "github.com/adedayo/vantage/pkg"
)

// lookupTXTWithServer is a server-parameterised TXT lookup.
func lookupTXTWithServer(ctx context.Context, r d.Resolver, name, server string) ([]string, error) {
	resp, err := r.ExchangeWithServer(ctx, server, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var txts []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			txts = append(txts, t.Txt...)
		}
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("error: not found")
	}
	return txts, nil
}

// LookupSPFWithServer is a server-parameterised version of LookupSPF.
func LookupSPFWithServer(ctx context.Context, r d.Resolver, domain, server string) (string, error) {
	txts, err := lookupTXTWithServer(ctx, r, domain, server)
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

// LookupDKIMWithServer is a server-parameterised version of LookupDKIM.
func LookupDKIMWithServer(ctx context.Context, r d.Resolver, domain, selector, server string) (string, error) {
	txts, err := lookupTXTWithServer(ctx, r, fmt.Sprintf("%s._domainkey.%s", selector, domain), server)
	if err != nil {
		return "", err
	}
	return txts[0], nil
}

// LookupDMARCWithServer is a server-parameterised version of LookupDMARC.
func LookupDMARCWithServer(ctx context.Context, r d.Resolver, domain, server string) (string, error) {
	txts, err := lookupTXTWithServer(ctx, r, "_dmarc."+domain, server)
	if err != nil {
		return "", err
	}
	return parseDMARCPolicy(txts)
}

// ParseDMARCReportingWithServer is a server-parameterised version of ParseDMARCReporting.
func ParseDMARCReportingWithServer(ctx context.Context, r d.Resolver, domain, server string) (rua []string, ruf []string, err error) {
	txts, err := lookupTXTWithServer(ctx, r, "_dmarc."+domain, server)
	if err != nil {
		return nil, nil, err
	}
	return parseDMARCReporting(txts)
}

// CheckMTAStsWithServer is a server-parameterised version of CheckMTASts.
func CheckMTAStsWithServer(ctx context.Context, r d.Resolver, domain, server string) (string, error) {
	txts, err := lookupTXTWithServer(ctx, r, "_mta-sts."+domain, server)
	if err != nil {
		return "", err
	}
	return txts[0], nil
}

// CheckDNSSECWithServer is a server-parameterised version of CheckDNSSEC.
func CheckDNSSECWithServer(ctx context.Context, r d.Resolver, domain, server string) (string, error) {
	resp, err := r.ExchangeWithServer(ctx, server, domain, dns.TypeDNSKEY)
	if err != nil {
		return "", err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("error: dns response code %d", resp.Rcode)
	}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.DNSKEY); ok {
			return "enabled", nil
		}
	}
	return "not found", nil
}

// lookupTLSAWithServer queries TLSA records for an arbitrary name.
func lookupTLSAWithServer(ctx context.Context, r d.Resolver, name, server string) (string, error) {
	resp, err := r.ExchangeWithServer(ctx, server, name, dns.TypeTLSA)
	if err != nil {
		return "", err
	}
	return formatTLSA(resp.Answer)
}

// LookupTLSAHTTPSWithServer is a server-parameterised version of LookupTLSAHTTPS.
func LookupTLSAHTTPSWithServer(ctx context.Context, r d.Resolver, domain, server string) (string, error) {
	return lookupTLSAWithServer(ctx, r, "_443._tcp."+domain, server)
}

// LookupTLSASSHWithServer is a server-parameterised version of LookupTLSASSH.
func LookupTLSASSHWithServer(ctx context.Context, r d.Resolver, domain, server string) (string, error) {
	return lookupTLSAWithServer(ctx, r, "_22._tcp."+domain, server)
}

// LookupTLASSMTPWithServer is a server-parameterised version of LookupTLASSMTP.
func LookupTLASSMTPWithServer(ctx context.Context, r d.Resolver, domain, server string) (string, error) {
	return lookupTLSAWithServer(ctx, r, "_25._tcp."+domain, server)
}

// LookupCAAWithServer is a server-parameterised version of LookupCAA.
func LookupCAAWithServer(ctx context.Context, r d.Resolver, domain, server string) ([]string, error) {
	resp, err := r.ExchangeWithServer(ctx, server, domain, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	return formatCAA(resp.Answer)
}

// VerifyNSSECWithServer is a server-parameterised version of VerifyNSSEC.
func VerifyNSSECWithServer(ctx context.Context, r d.Resolver, domain, server string) (bool, error) {
	for _, qtype := range []uint16{dns.TypeNSEC, dns.TypeNSEC3} {
		resp, err := r.ExchangeWithServer(ctx, server, domain, qtype)
		if err == nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// CheckDNSBLWithServer queries the DNSBL for a given net.IP using the provided
// server, bypassing address resolution so callers can control the IP under test.
func CheckDNSBLWithServer(ctx context.Context, r d.Resolver, ip net.IP, blocklist, server string) (bool, error) {
	ip4 := firstIPv4([]net.IP{ip})
	if ip4 == nil {
		return false, fmt.Errorf("error: no IPv4 address for DNSBL check")
	}
	resp, err := r.ExchangeWithServer(ctx, server, dnsblQueryName(ip4, blocklist), dns.TypeA)
	if err != nil {
		return false, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false, nil
	}
	return len(resp.Answer) > 0, nil
}
