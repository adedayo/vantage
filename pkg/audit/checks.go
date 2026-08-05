package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/scanner"
)

// This file adapts the existing checks to the Check interface and registers
// them. Registration is the only step needed to expose a check everywhere:
// the CLI, the profiles and, in due course, the capability manifest.
//
// Checks whose analysis rules are not yet written (spec 011) still register
// here. They contribute their records and their state to the result, which is
// worth having on its own, and they gain findings the moment their rules land.

func init() {
	Register(spfCheck())
	Register(dmarcCheck())
	Register(dkimCheck())
	Register(mxCheck())
	Register(dnssecCheck())
	Register(nssecCheck())
	Register(caaCheck())
	Register(mtastsCheck())
	Register(ptrCheck())
	Register(tlsrptCheck())
	Register(bimiCheck())
	Register(wildcardCheck())
	Register(delegationCheck())
	Register(takeoverCheck())
	Register(zoneTransferCheck())
	Register(networkCheck())
	Register(certificateTransparencyCheck())
}

// notFound reports the absent state without treating it as a failure.
func notFound(findings ...finding.Finding) (Outcome, error) {
	return Outcome{State: finding.StateNotFound, Findings: findings}, nil
}

// isAbsent reports whether an error means the record is definitively absent.
func isAbsent(err error) bool {
	return errors.Is(err, vantage.ErrNotFound) || strings.Contains(err.Error(), "not found")
}

func spfCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "spf",
			Summary:        "Sender Policy Framework: which hosts may send mail as the domain.",
			Egress:         EgressProfile{Resolver: true},
			Findings:       findingIDs("spf"),
			TypicalQueries: 12,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			txts, server, err := t.Cache.LookupTXT(ctx, t.Domain)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
					records = append(records, txt)
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.SPFRecursive(ctx, origin,
				cacheResolver{t.Cache}, records, sendsMail(ctx, t))
			if len(records) == 0 {
				return notFound(findings...)
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func dmarcCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "dmarc",
			Summary:        "DMARC policy: what receivers should do with unauthenticated mail.",
			Egress:         EgressProfile{Resolver: true},
			Findings:       findingIDs("dmarc"),
			TypicalQueries: 3,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			name := "_dmarc." + t.Domain
			txts, server, err := t.Cache.LookupTXT(ctx, name)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToUpper(txt), "V=DMARC1") {
					records = append(records, txt)
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.DMARCFull(ctx, origin, cacheDMARCResolver{t.Cache},
				records, organisationalDomain(t.Domain))
			if len(records) == 0 {
				return notFound(findings...)
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

// commonDKIMSelectors are the selectors used by the major mail providers.
//
// Probing them is inference, not proof: a domain may use a selector nobody can
// guess. The check therefore reports what it finds but never concludes DKIM is
// absent, because "we looked in the obvious places" is not the same as "it is
// not there" — and reporting the latter would be a plain falsehood.
var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "s1", "s2",
	"mail", "dkim", "mandrill", "zoho", "everlytickey1", "sig1",
}

func dkimCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "dkim",
			Summary: "DKIM signing keys, probed across the selectors used by common " +
				"providers.",
			Egress:         EgressProfile{Resolver: true},
			Findings:       findingIDs("dkim"),
			TypicalQueries: len(commonDKIMSelectors),
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			var (
				records []string
				keys    []analyse.DKIMKey
				server  string
			)
			for _, selector := range commonDKIMSelectors {
				name := selector + "._domainkey." + t.Domain
				txts, from, err := t.Cache.LookupTXT(ctx, name)
				if err != nil {
					continue
				}
				for _, txt := range txts {
					if !strings.Contains(txt, "p=") {
						continue
					}
					if server == "" {
						server = from
					}
					records = append(records, selector+": "+txt)
					keys = append(keys, analyse.ParseDKIM(selector, txt))
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.DKIM(origin, keys, true)
			if len(records) == 0 {
				// Not "absent": DKIM selectors cannot be enumerated from DNS,
				// so a miss across the common ones proves nothing. Reporting
				// this as not-found would invite the reader to conclude a
				// control is missing when it may simply use a private selector.
				return Outcome{State: finding.StateNotChecked, Findings: findings}, nil
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func mxCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "mx",
			Summary:        "Mail exchangers published by the domain, and their hygiene.",
			Egress:         EgressProfile{Resolver: true},
			Findings:       findingIDs("mx"),
			TypicalQueries: 6,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			msg, _, err := t.Cache.Exchange(ctx, t.Domain, dns.TypeMX)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}
			var records []string
			if msg != nil {
				for _, rr := range msg.Answer {
					if mx, ok := rr.(*dns.MX); ok {
						records = append(records, fmt.Sprintf("%d %s", mx.Preference, mx.Mx))
					}
				}
			}

			origin := analyse.Origin{Target: t.Domain}
			hosts := resolveMXHosts(ctx, t.Cache, analyse.ParseMX(records))
			findings := analyse.MX(origin, hosts, hasAddress(ctx, t.Cache, t.Domain))

			if len(records) == 0 {
				return notFound(findings...)
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func dnssecCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "dnssec",
			Summary: "DNSSEC chain of trust: keys, parent delegation, algorithms, " +
				"signature validity and denial of existence.",
			Egress:   EgressProfile{Resolver: true},
			Findings: findingIDs("dnssec"),
			// DNSKEY, DS, SOA, NSEC3PARAM and a denial probe. These queries set
			// the DO bit, so they are made directly rather than through the run
			// cache, whose answers are collected without DNSSEC records.
			TypicalQueries: 5,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			zone, err := scanner.FetchDNSSECZone(ctx, t.Cache.Resolver(), t.Domain)
			if err != nil {
				if isAbsent(err) {
					return notFound(analyse.DNSSEC(analyse.Origin{Target: t.Domain}, zone)...)
				}
				return Outcome{}, err
			}

			origin := analyse.Origin{Target: t.Domain, Source: zone.Source}
			findings := analyse.DNSSEC(origin, zone)
			if !zone.Signed() {
				return notFound(findings...)
			}
			return Outcome{
				State:    finding.StateOK,
				Records:  analyse.DNSSECRecords(zone),
				Findings: findings,
			}, nil
		},
	}
}

func nssecCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "nssec",
			Summary:        "NSEC/NSEC3 denial-of-existence records.",
			Egress:         EgressProfile{Resolver: true},
			Findings:       nil,
			TypicalQueries: 1,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			present, err := scanner.VerifyNSSEC(ctx, t.Cache.Resolver(), t.Domain)
			if err != nil {
				if isAbsent(err) {
					return notFound()
				}
				return Outcome{}, err
			}
			if !present {
				return notFound()
			}
			return Outcome{State: finding.StateOK, Records: []string{"NSEC/NSEC3 present"}}, nil
		},
	}
}

func caaCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "caa",
			Summary:        "Certification Authority Authorisation: which CAs may issue.",
			Egress:         EgressProfile{Resolver: true},
			Findings:       findingIDs("caa"),
			TypicalQueries: 3,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			policy := climbCAA(ctx, t.Cache, t.Domain)
			findings := analyse.CAA(analyse.Origin{Target: t.Domain}, policy)

			if len(policy.Records) == 0 {
				return notFound(findings...)
			}

			records := make([]string, 0, len(policy.Records))
			for _, r := range policy.Records {
				records = append(records,
					fmt.Sprintf("%d %s %q", r.Flags, r.Tag, r.Value))
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func mtastsCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:    "mtasts",
			Summary: "MTA-STS: enforced TLS for inbound mail, including the policy file.",
			// The policy file is fetched over HTTPS, but the check is not
			// excluded by --no-network: the TXT record alone reveals whether
			// MTA-STS is published at all, which is the finding that matters
			// most. In that mode only the policy-dependent rules are skipped.
			Egress:                 EgressProfile{Resolver: true, TargetHTTPS: true},
			DegradesWithoutNetwork: true,
			Findings:               findingIDs("mtasts"),
			TypicalQueries:         2,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			name := "_mta-sts." + t.Domain
			txts, server, err := t.Cache.LookupTXT(ctx, name)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToUpper(txt), "V=STSV1") {
					records = append(records, txt)
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}

			// A zero policy means no fetch was attempted, which suppresses the
			// rules that depend on the policy file rather than reporting them
			// as failures.
			var policy analyse.MTASTSPolicy
			if len(records) > 0 && !t.NoNetwork {
				policy = scanner.FetchMTASTSPolicy(ctx, t.Cache.Resolver(), t.Cache.HTTP(), t.Domain)
			}

			findings := analyse.MTASTS(origin, records, policy, mxHosts(ctx, t.Cache, t.Domain))
			if len(records) == 0 {
				return notFound(findings...)
			}

			if policy.Raw != "" {
				// Record the policy as its own lines, so the retrieved
				// evidence is readable rather than a whitespace-split blob.
				for _, line := range strings.Split(policy.Raw, "\n") {
					if line = strings.TrimSpace(line); line != "" {
						records = append(records, line)
					}
				}
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func ptrCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "ptr",
			Summary:        "Reverse DNS for the domain's addresses.",
			Egress:         EgressProfile{Resolver: true},
			Findings:       nil,
			TypicalQueries: 2,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			record, err := scanner.ReverseLookupPTR(ctx, t.Cache.Resolver(), t.Domain)
			if err != nil {
				if isAbsent(err) {
					return notFound()
				}
				return Outcome{}, err
			}
			return Outcome{State: finding.StateOK, Records: []string{record}}, nil
		},
	}
}

func tlsrptCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "tlsrpt",
			Summary: "SMTP TLS Reporting: where receivers report failures to negotiate " +
				"TLS with the domain's mail exchangers.",
			Egress:         EgressProfile{Resolver: true},
			Findings:       findingIDs("tlsrpt"),
			TypicalQueries: 1,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			name := "_smtp._tls." + t.Domain
			txts, server, err := t.Cache.LookupTXT(ctx, name)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToUpper(txt), "V=TLSRPTV1") {
					records = append(records, txt)
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.TLSRPT(origin, records)
			if len(records) == 0 {
				return notFound(findings...)
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func bimiCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "bimi",
			Summary:        "Brand Indicators for Message Identification (default._bimi).",
			Egress:         EgressProfile{Resolver: true},
			Findings:       findingIDs("bimi"),
			TypicalQueries: 2,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			name := "default._bimi." + t.Domain
			txts, server, err := t.Cache.LookupTXT(ctx, name)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToUpper(txt), "V=BIMI1") {
					records = append(records, txt)
				}
			}

			if len(records) == 0 {
				// Absence is not a finding: BIMI is optional branding, so the
				// analysis is only run when a record exists.
				return notFound()
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.BIMI(origin, records, dmarcEnforcing(ctx, t.Cache, t.Domain))
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func wildcardCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "wild",
			Summary: "Wildcard records: whether the zone answers for names that were " +
				"never registered.",
			Egress:         EgressProfile{Resolver: true, TargetNameservers: true},
			Findings:       findingIDs("wild"),
			TypicalQueries: wildcardProbeCount * 4,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			obs, err := probeWildcard(ctx, t.Cache, t.Domain)
			if err != nil {
				return Outcome{}, err
			}

			origin := analyse.Origin{Target: t.Domain}
			findings := analyse.Wildcard(origin, obs)
			records := wildcardRecords(obs)
			if len(records) == 0 {
				// No wildcard is the expected and healthy case. It is reported
				// as absence of a record rather than as a failure, so a reader
				// can tell it from a check that could not run.
				return notFound()
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func delegationCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "ns",
			Summary: "Nameserver and delegation hygiene: redundancy, lame servers, " +
				"glue, parent agreement and open recursion.",
			Egress:   EgressProfile{Resolver: true, TargetNameservers: true},
			Findings: findingIDs("ns"),
			// The NS set, the parent referral, then per nameserver: addresses,
			// an SOA query and a recursion probe.
			TypicalQueries: 12,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			del, err := fetchDelegation(ctx, t.Cache, t.Domain)
			if err != nil {
				return Outcome{}, err
			}
			if len(del.Nameservers) == 0 {
				return notFound()
			}

			findings := analyse.DelegationHygiene(analyse.Origin{Target: t.Domain}, del)
			return Outcome{
				State:    finding.StateOK,
				Records:  delegationRecords(del),
				Findings: findings,
			}, nil
		},
	}
}

func takeoverCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "tko",
			Summary: "Subdomain takeover: aliases to third-party services that no " +
				"longer hold the name.",
			Egress: EgressProfile{Resolver: true, TargetNameservers: true, TargetHTTPS: true},
			// DNS alone finds the dangling-alias cases, which are the
			// highest-severity ones. HTTPS only adds corroboration for
			// services that keep the target resolvable, so --no-network
			// narrows this check rather than removing it.
			DegradesWithoutNetwork: true,
			Findings:               findingIDs("tko"),
			// The apex and each supplied host: a CNAME query and two existence
			// queries, plus the wildcard probes and the NS set.
			TypicalQueries: 18,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			obs, err := fetchTakeover(ctx, t.Cache, t.Domain, t.Hosts, !t.NoNetwork)
			if err != nil {
				return Outcome{}, err
			}

			findings := analyse.Takeover(analyse.Origin{Target: t.Domain}, obs)
			records := takeoverRecords(obs)
			if len(records) == 0 && len(findings) == 0 {
				// No aliases to assess. This is absence of the thing being
				// looked for, not a clean bill of health for hosts nobody
				// named: the check is only as broad as the host list given.
				return notFound()
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func zoneTransferCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "axfr",
			Summary: "Zone transfer: whether any authoritative server hands the whole " +
				"zone to an anonymous client.",
			// A zone transfer request goes to the target's own authoritative
			// servers and asks for more than an ordinary query does, so it is
			// declared intrusive and a deployment must consent before it runs.
			Egress:   EgressProfile{Resolver: true, TargetNameservers: true, Intrusive: true},
			Findings: findingIDs("axfr"),
			// The NS set, each server's address, then one TCP attempt each.
			TypicalQueries: 10,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			obs, err := attemptZoneTransfers(ctx, t.Cache, t.Domain)
			if err != nil {
				return Outcome{}, err
			}
			if len(obs.Attempts) == 0 {
				return notFound()
			}

			findings := analyse.ZoneTransfer(analyse.Origin{Target: t.Domain}, obs)
			records := analyse.ZoneTransferRecords(obs)

			// If no server actually answered, the zone was not assessed. It
			// must not be reported as "ok" with no findings: an operator
			// reading a clean result for a check that never completed would
			// conclude transfers are restricted when nothing was established
			// either way. Outbound TCP/53 is blocked on plenty of corporate
			// networks, which makes this the common case rather than a rare
			// one.
			if !analyse.ZoneTransferAssessed(obs) {
				return Outcome{
					State:   finding.StateCheckFailed,
					Records: records,
				}, fmt.Errorf("error: no authoritative server answered a zone transfer request for %s", t.Domain)
			}

			return Outcome{
				State:    finding.StateOK,
				Records:  records,
				Findings: findings,
			}, nil
		},
	}
}

func networkCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "net",
			Summary: "Network attribution: which provider and jurisdiction the domain's " +
				"hosts actually resolve into, and whether any leak internal addressing.",
			// The provider ranges are fetched from each operator's own
			// publication, which is egress to a third party rather than to the
			// target.
			Egress: EgressProfile{
				Resolver: true,
				ThirdParty: []ThirdPartyService{
					ServiceAWSRanges, ServiceGCPRanges,
					ServiceCloudflareRanges, ServiceFastlyRanges,
				},
			},
			// Internal-address leakage is decided from the IANA registries
			// embedded in the binary, so the most serious rule here works with
			// no egress at all. Only provider and jurisdiction attribution
			// needs the downloads.
			DegradesWithoutNetwork: true,
			Findings:               findingIDs("net"),
			// The apex, the MX set, the NS set and each supplied host, twice
			// over for A and AAAA.
			TypicalQueries: 16,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			obs, err := fetchNetworkAttribution(ctx, t.Cache, t.Domain,
				hostsWithin(t.Domain, t.Hosts), t.ExpectJurisdictions, t.NoNetwork)
			if err != nil {
				return Outcome{}, err
			}
			if len(obs.Hosts) == 0 {
				return notFound()
			}

			return Outcome{
				State:    finding.StateOK,
				Records:  analyse.NetworkRecords(obs),
				Findings: analyse.NetworkAttribution(analyse.Origin{Target: t.Domain}, obs),
			}, nil
		},
	}
}

func certificateTransparencyCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "ct",
			Summary: "Certificate Transparency: hostnames the organisation has certified, " +
				"including ones that no longer resolve.",
			// The logs are a third party. Nothing here touches the target's
			// own infrastructure beyond resolving the names discovered.
			Egress: EgressProfile{
				Resolver:   true,
				ThirdParty: []ThirdPartyService{ServiceCertSpotter, ServiceCRTSh},
			},
			// Without the logs there are no names to assess and nothing to
			// report, so under --no-network this check has no reduced form to
			// fall back on and is excluded honestly rather than run blind.
			DegradesWithoutNetwork: false,
			Findings:               findingIDs("ct"),
			// One query to the log service, then up to four DNS queries for
			// each discovered name.
			TypicalQueries: 60,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			obs, err := enumerateCT(ctx, t.Cache, t.Domain)
			if err != nil {
				return Outcome{}, err
			}
			if obs.CertificateCount == 0 {
				// No certificate has ever been issued for the domain. That is
				// absence of the thing being looked for, not a clean result.
				return notFound()
			}

			return Outcome{
				State:    finding.StateOK,
				Records:  analyse.CTRecords(obs),
				Findings: analyse.CertificateTransparency(analyse.Origin{Target: t.Domain}, obs),
			}, nil
		},
	}
}

// sendsMail reports whether the domain publishes usable MX records, reusing the
//
// A failed lookup returns true: assuming the domain sends mail keeps a missing
// SPF record at its full severity. Downgrading a real problem on the strength
// of a query that did not complete is the wrong direction in which to be wrong.
func sendsMail(ctx context.Context, t Target) bool {
	msg, _, err := t.Cache.Exchange(ctx, t.Domain, dns.TypeMX)
	if err != nil {
		return !isAbsent(err)
	}
	for _, rr := range msg.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			if host := strings.TrimSpace(mx.Mx); host != "" && host != "." {
				return true
			}
		}
	}
	return false
}

// findingIDs returns the catalogue IDs belonging to a check, so a check's
// declared findings are derived from the catalogue rather than restated.
func findingIDs(check string) []string {
	entries := finding.CatalogueForCheck(check)
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	return ids
}
