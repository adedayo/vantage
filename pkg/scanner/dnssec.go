package scanner

// dnssec.go gathers the records needed to assess a zone's chain of trust.
//
// Every query here sets the EDNS0 DO bit, without which a resolver strips the
// RRSIG records and the AD bit is meaningless — leaving the caller unable to
// tell a properly validating zone from an unsigned one.

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"

	d "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
)

// nxLabel is prefixed to the domain to provoke an authenticated denial of
// existence, which is the only reliable way to see the NSEC or NSEC3 records a
// zone actually serves. Querying NSEC3 directly at the apex returns nothing in
// most deployments, because the records live at hashed owner names.
//
// The label is fixed rather than random so that repeated runs share a resolver
// cache entry instead of generating fresh negative-cache load on every audit.
const nxLabel = "_vantage-nonexistent."

// dnssecExchanger performs one DNSSEC-aware query. Parameterising it lets the
// tests drive the collector against a local mock server.
type dnssecExchanger func(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error)

// FetchDNSSECZone retrieves the DNSKEY, DS, RRSIG and denial-of-existence
// records for a domain, using the system resolvers.
func FetchDNSSECZone(ctx context.Context, r d.Resolver, domain string) (analyse.DNSSECZone, error) {
	return fetchDNSSECZone(ctx, domain, r.ExchangeDNSSECRawFrom)
}

// FetchDNSSECZoneWithServer is a server-parameterised version of
// FetchDNSSECZone.
func FetchDNSSECZoneWithServer(ctx context.Context, r d.Resolver, domain, server string) (analyse.DNSSECZone, error) {
	return fetchDNSSECZone(ctx, domain, func(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error) {
		msg, err := r.ExchangeDNSSECWithServer(ctx, server, name, qtype)
		return msg, server, err
	})
}

// fetchDNSSECZone performs the collection.
//
// Individual query failures are tolerated: a resolver that refuses DS queries
// should not prevent the key material from being reported. Only a complete
// failure to learn anything about the zone is an error, because that is the
// case where silence would be indistinguishable from "not signed" — a
// conclusion the evidence does not support.
//
// The resolver is not a parameter. Every query goes through exchange, which
// the exported wrappers bind to one; taking a second would let a caller supply
// a resolver that was then silently ignored.
func fetchDNSSECZone(ctx context.Context, domain string, exchange dnssecExchanger) (analyse.DNSSECZone, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	zone := analyse.DNSSECZone{}

	keysMsg, keyServer, keyErr := exchange(ctx, domain, dns.TypeDNSKEY)
	dsMsg, _, dsErr := exchange(ctx, domain, dns.TypeDS)
	if keyErr != nil && dsErr != nil {
		return zone, keyErr
	}

	var rawKeys []*dns.DNSKEY
	if keysMsg != nil {
		zone.Source = keyServer
		zone.AuthenticatedData = keysMsg.AuthenticatedData
		for _, rr := range keysMsg.Answer {
			switch r := rr.(type) {
			case *dns.DNSKEY:
				rawKeys = append(rawKeys, r)
				zone.Keys = append(zone.Keys, analyse.DNSKEY{
					KeyTag:    r.KeyTag(),
					Flags:     r.Flags,
					Algorithm: r.Algorithm,
					PublicKey: r.PublicKey,
				})
			case *dns.RRSIG:
				zone.Signatures = append(zone.Signatures, convertRRSIG(r))
			}
		}
	}

	if dsMsg != nil {
		for _, rr := range dsMsg.Answer {
			if ds, ok := rr.(*dns.DS); ok {
				zone.DS = append(zone.DS, convertDS(ds, rawKeys))
			}
		}
	}

	// The SOA carries its own RRSIG and is resigned on the same schedule as
	// the rest of the zone, so it is a good proxy for signature freshness even
	// where the DNSKEY set is signed separately.
	if soa, _, err := exchange(ctx, domain, dns.TypeSOA); err == nil && soa != nil {
		for _, rr := range soa.Answer {
			if sig, ok := rr.(*dns.RRSIG); ok {
				zone.Signatures = append(zone.Signatures, convertRRSIG(sig))
			}
		}
	}

	collectDenialOfExistence(ctx, domain, exchange, &zone)
	return zone, nil
}

// collectDenialOfExistence learns which form of authenticated denial the zone
// serves, and with what NSEC3 parameters.
//
// It takes no resolver: all egress goes through exchange, which is already
// bound to one. Accepting a second would let a caller pass a resolver that was
// then quietly ignored, which is the kind of gap that turns a scope guard into
// decoration.
func collectDenialOfExistence(ctx context.Context, domain string, exchange dnssecExchanger, zone *analyse.DNSSECZone) {
	// NSEC3PARAM is authoritative about the parameters when it is published.
	if msg, _, err := exchange(ctx, domain, dns.TypeNSEC3PARAM); err == nil && msg != nil {
		for _, rr := range msg.Answer {
			if p, ok := rr.(*dns.NSEC3PARAM); ok {
				zone.NSEC3 = true
				zone.NSEC3Iterations = int(p.Iterations)
			}
		}
	}

	// A denial response reveals what the zone actually serves, which is the
	// only evidence that settles the NSEC-versus-NSEC3 question for zones that
	// publish no NSEC3PARAM.
	msg, _, err := exchange(ctx, nxLabel+domain, dns.TypeA)
	if err != nil || msg == nil {
		return
	}
	for _, rr := range msg.Ns {
		switch r := rr.(type) {
		case *dns.NSEC:
			zone.NSEC = true
			zone.NSECSynthesised = zone.NSECSynthesised || isSynthesisedNSEC(r, nxLabel+domain)
		case *dns.NSEC3:
			zone.NSEC3 = true
			if int(r.Iterations) > zone.NSEC3Iterations {
				zone.NSEC3Iterations = int(r.Iterations)
			}
		}
	}
}

// isSynthesisedNSEC recognises an NSEC record generated for the query rather
// than drawn from a pre-signed chain.
//
// Several large providers answer denials with an NSEC whose owner is the
// queried name and whose next name is that name's immediate successor. Nothing
// links it to the zone's real contents, so the chain cannot be walked. Reporting
// such a zone as enumerable would be a plain falsehood, and one that would
// train readers to ignore the finding where it does matter.
func isSynthesisedNSEC(rr *dns.NSEC, queried string) bool {
	owner := strings.ToLower(rr.Hdr.Name)
	next := strings.ToLower(rr.NextDomain)

	if !strings.EqualFold(owner, dns.Fqdn(queried)) {
		return false
	}
	// The successor is the owner prefixed with the lowest possible label,
	// which miekg/dns renders as an escaped null byte.
	return strings.HasPrefix(next, `\000.`) || next == `\000.`+owner
}

// epochToTime converts an RRSIG timestamp to a time.Time.
//
// RFC 4034 §3.1.5 defines these fields with serial-number arithmetic modulo
// 2^32, not as plain Unix seconds, so the value is interpreted relative to the
// current time. Treating it as a bare epoch would work until 2106 and then
// report every zone on earth as catastrophically expired.
func epochToTime(ts uint32) time.Time {
	const wrap = int64(1) << 32
	now := time.Now().Unix()
	// Place the timestamp in the 2^32-second window centred on now.
	base := (now / wrap) * wrap
	candidate := base + int64(ts)
	switch {
	case candidate-now > wrap/2:
		candidate -= wrap
	case now-candidate > wrap/2:
		candidate += wrap
	}
	return time.Unix(candidate, 0).UTC()
}

// convertRRSIG converts a signature record to its analysis form.
func convertRRSIG(sig *dns.RRSIG) analyse.RRSIG {
	return analyse.RRSIG{
		TypeCovered: dns.TypeToString[sig.TypeCovered],
		Algorithm:   sig.Algorithm,
		KeyTag:      sig.KeyTag,
		SignerName:  strings.TrimSuffix(sig.SignerName, "."),
		Expiration:  epochToTime(sig.Expiration),
		Inception:   epochToTime(sig.Inception),
	}
}

// convertDS converts a delegation signer record, recomputing the digest from
// any candidate key so that a tag collision or a stale DS is caught rather than
// reported as a working chain.
func convertDS(ds *dns.DS, keys []*dns.DNSKEY) analyse.DS {
	out := analyse.DS{
		KeyTag:     ds.KeyTag,
		Algorithm:  ds.Algorithm,
		DigestType: ds.DigestType,
	}

	var candidates, matches int
	for _, k := range keys {
		if k.KeyTag() != ds.KeyTag || k.Algorithm != ds.Algorithm {
			continue
		}
		candidates++
		if computed := k.ToDS(ds.DigestType); computed != nil &&
			strings.EqualFold(computed.Digest, ds.Digest) {
			matches++
		}
	}
	// Only claim a mismatch when a key was actually available to compare
	// against: absent keys are a different finding, reported elsewhere.
	out.DigestMismatch = candidates > 0 && matches == 0
	return out
}
