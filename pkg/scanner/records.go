package scanner

import (
	"context"
	"strings"

	"github.com/miekg/dns"

	d "github.com/adedayo/vantage/pkg"
)

// LookupMX returns the mail exchangers published by a domain, formatted as
// "<preference> <host>". An absent MX set is not an error: it is a legitimate
// and meaningful state that callers need to distinguish from a lookup failure.
func LookupMX(ctx context.Context, r d.Resolver, domain string) ([]string, error) {
	msg, _, err := r.ExchangeFrom(ctx, domain, dns.TypeMX)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
	var records []string
	for _, rr := range msg.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			records = append(records, strings.TrimSpace(
				strings.TrimSuffix(mx.Mx, ".")))
		}
	}
	return records, nil
}

// SendsMail reports whether a domain appears to send or receive mail, which
// governs how seriously a missing SPF or DMARC record should be treated.
//
// A lookup failure returns true: assuming the domain does send mail is the
// conservative choice, because it keeps the severity high rather than quietly
// downgrading a real problem on the strength of a failed query.
func SendsMail(ctx context.Context, r d.Resolver, domain string) bool {
	records, err := LookupMX(ctx, r, domain)
	if err != nil {
		return true
	}
	for _, r := range records {
		// A null MX ("0 .") explicitly declares that the domain sends no mail.
		if r != "" && r != "." {
			return true
		}
	}
	return false
}

// LookupSPFRecords returns every TXT record at the domain apex that begins with
// "v=spf1".
//
// LookupSPF returns only the first such record, which is the right answer for
// simple retrieval but hides a real misconfiguration: RFC 7208 requires
// receivers to return PermError when a domain publishes more than one SPF
// record, so the protection the operator believes is in place is not applied at
// all. Analysis therefore needs the full set, not just the first.
func LookupSPFRecords(ctx context.Context, r d.Resolver, domain string) ([]string, error) {
	records, _, err := LookupSPFRecordsFrom(ctx, r, domain)
	return records, err
}

// LookupSPFRecordsFrom behaves like LookupSPFRecords but also reports which
// resolver answered, so that findings can attribute their evidence.
func LookupSPFRecordsFrom(ctx context.Context, r d.Resolver, domain string) ([]string, string, error) {
	txts, server, err := d.LookupTXTFrom(ctx, r, domain)
	if err != nil {
		return nil, server, err
	}
	var records []string
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			records = append(records, txt)
		}
	}
	return records, server, nil
}

// LookupDMARCRecords returns every TXT record at _dmarc.<domain> that begins
// with "v=DMARC1". As with SPF, publishing more than one is a misconfiguration
// that causes receivers to ignore the policy entirely, so the caller needs all
// of them.
func LookupDMARCRecords(ctx context.Context, r d.Resolver, domain string) ([]string, error) {
	records, _, err := LookupDMARCRecordsFrom(ctx, r, domain)
	return records, err
}

// LookupDMARCRecordsFrom behaves like LookupDMARCRecords but also reports which
// resolver answered.
func LookupDMARCRecordsFrom(ctx context.Context, r d.Resolver, domain string) ([]string, string, error) {
	txts, server, err := d.LookupTXTFrom(ctx, r, "_dmarc."+strings.TrimSuffix(domain, "."))
	if err != nil {
		return nil, server, err
	}
	var records []string
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToUpper(txt), "V=DMARC1") {
			records = append(records, txt)
		}
	}
	return records, server, nil
}

// LookupTLSRPTRecordsFrom returns every TXT record at _smtp._tls.<domain> that
// begins with "v=TLSRPTv1", together with the resolver that answered.
func LookupTLSRPTRecordsFrom(ctx context.Context, r d.Resolver, domain string) ([]string, string, error) {
	txts, server, err := d.LookupTXTFrom(ctx, r, "_smtp._tls."+strings.TrimSuffix(domain, "."))
	if err != nil {
		return nil, server, err
	}
	var records []string
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToUpper(txt), "V=TLSRPTV1") {
			records = append(records, txt)
		}
	}
	return records, server, nil
}

// LookupMTASTSRecordsFrom returns every TXT record at _mta-sts.<domain> that
// begins with "v=STSv1", together with the resolver that answered.
func LookupMTASTSRecordsFrom(ctx context.Context, r d.Resolver, domain string) ([]string, string, error) {
	txts, server, err := d.LookupTXTFrom(ctx, r, "_mta-sts."+strings.TrimSuffix(domain, "."))
	if err != nil {
		return nil, server, err
	}
	var records []string
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToUpper(txt), "V=STSV1") {
			records = append(records, txt)
		}
	}
	return records, server, nil
}

// LookupBIMIRecordsFrom returns every TXT record at default._bimi.<domain>
// that begins with "v=BIMI1", together with the resolver that answered.
func LookupBIMIRecordsFrom(ctx context.Context, r d.Resolver, domain string) ([]string, string, error) {
	txts, server, err := d.LookupTXTFrom(ctx, r, "default._bimi."+strings.TrimSuffix(domain, "."))
	if err != nil {
		return nil, server, err
	}
	var records []string
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToUpper(txt), "V=BIMI1") {
			records = append(records, txt)
		}
	}
	return records, server, nil
}

// LookupDKIMRecordsFrom returns the DKIM key records published at
// <selector>._domainkey.<domain>, together with the resolver that answered.
//
// Records are filtered on the presence of a p= tag rather than on the v=DKIM1
// tag, because the version tag is optional in RFC 6376 and omitting it is
// common enough that requiring it would hide real keys.
func LookupDKIMRecordsFrom(ctx context.Context, r d.Resolver, domain, selector string) ([]string, string, error) {
	name := selector + "._domainkey." + strings.TrimSuffix(domain, ".")
	txts, server, err := d.LookupTXTFrom(ctx, r, name)
	if err != nil {
		return nil, server, err
	}
	var records []string
	for _, txt := range txts {
		if txt = strings.TrimSpace(txt); strings.Contains(txt, "p=") {
			records = append(records, txt)
		}
	}
	return records, server, nil
}
