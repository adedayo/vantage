package scanner_test

// dnssec_test.go exercises the DNSSEC collector against a local mock zone,
// including the cases that are impossible to observe against real domains on
// demand: a stale DS, an unsigned delegation, and an NSEC-only zone.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/scanner"
)

// signingKey generates a DNSKEY with usable RSA key material, so that digests
// and key tags are computed from real values rather than fixtures that only
// look plausible.
func signingKey(t *testing.T, zone string) *dns.DNSKEY {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY,
			Class: dns.ClassINET, Ttl: 3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	_, err := key.Generate(1024)
	require.NoError(t, err)
	return key
}

// zoneOptions describes the mock zone a test wants served.
type zoneOptions struct {
	key             *dns.DNSKEY
	ds              *dns.DS
	rrsigExpiration uint32
	nsec3           bool
	nsec3Iterations uint16
	nsec            bool
	synthesisedNSEC bool
	authenticated   bool
}

// serveZone registers handlers for one signed zone.
func serveZone(t *testing.T, name string, opts zoneOptions) (addr string, stop func()) {
	t.Helper()
	fqdn := dns.Fqdn(name)

	mux := dns.NewServeMux()
	mux.HandleFunc(fqdn, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.AuthenticatedData = opts.authenticated

		hdr := func(rrtype uint16) dns.RR_Header {
			return dns.RR_Header{Name: fqdn, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
		}

		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeDNSKEY:
			if opts.key != nil {
				m.Answer = append(m.Answer, opts.key)
			}
			if opts.rrsigExpiration != 0 {
				m.Answer = append(m.Answer, &dns.RRSIG{
					Hdr: hdr(dns.TypeRRSIG), TypeCovered: dns.TypeDNSKEY,
					Algorithm: dns.RSASHA256, KeyTag: 1234, SignerName: fqdn,
					Expiration: opts.rrsigExpiration,
					Inception:  uint32(time.Now().Add(-24 * time.Hour).Unix()),
				})
			}
		case dns.TypeDS:
			if opts.ds != nil {
				m.Answer = append(m.Answer, opts.ds)
			}
		case dns.TypeNSEC3PARAM:
			if opts.nsec3 {
				m.Answer = append(m.Answer, &dns.NSEC3PARAM{
					Hdr: hdr(dns.TypeNSEC3PARAM), Hash: 1,
					Iterations: opts.nsec3Iterations,
				})
			}
		case dns.TypeSOA:
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr: hdr(dns.TypeSOA), Ns: "ns." + fqdn, Mbox: "hostmaster." + fqdn,
				Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
			})
		}

		// Anything below the apex is a denial, which is where the NSEC or
		// NSEC3 record the zone actually serves becomes visible.
		if q.Name != fqdn {
			m.Answer = nil
			m.Rcode = dns.RcodeNameError
			switch {
			case opts.nsec:
				next := "zzz." + fqdn
				if opts.synthesisedNSEC {
					next = `\000.` + q.Name
				}
				m.Ns = append(m.Ns, &dns.NSEC{
					Hdr: dns.RR_Header{
						Name: q.Name, Rrtype: dns.TypeNSEC,
						Class: dns.ClassINET, Ttl: 300,
					},
					NextDomain: next,
					TypeBitMap: []uint16{dns.TypeA},
				})
			case opts.nsec3:
				m.Ns = append(m.Ns, &dns.NSEC3{
					Hdr: dns.RR_Header{
						Name: "abcdef." + fqdn, Rrtype: dns.TypeNSEC3,
						Class: dns.ClassINET, Ttl: 300,
					},
					Hash: 1, Iterations: opts.nsec3Iterations, NextDomain: "ghijkl",
				})
			}
		}

		_ = w.WriteMsg(m)
	})

	return startMockDNS(t, mux)
}

func TestFetchDNSSECZoneCollectsTheChain(t *testing.T) {
	key := signingKey(t, "signed.test")
	expiry := uint32(time.Now().Add(30 * 24 * time.Hour).Unix())

	addr, stop := serveZone(t, "signed.test", zoneOptions{
		key:             key,
		ds:              key.ToDS(dns.SHA256),
		rrsigExpiration: expiry,
		nsec3:           true,
		authenticated:   true,
	})
	defer stop()

	zone, err := scanner.FetchDNSSECZoneWithServer(context.Background(), testResolver, "signed.test", addr)
	require.NoError(t, err)

	require.Len(t, zone.Keys, 1)
	assert.Equal(t, key.KeyTag(), zone.Keys[0].KeyTag)
	assert.Equal(t, dns.RSASHA256, zone.Keys[0].Algorithm)
	assert.Equal(t, 1024, zone.Keys[0].KeyBits())
	assert.True(t, zone.Keys[0].IsSecureEntryPoint())

	require.Len(t, zone.DS, 1)
	assert.Equal(t, key.KeyTag(), zone.DS[0].KeyTag)
	assert.False(t, zone.DS[0].DigestMismatch,
		"a DS whose digest matches the published key is a working chain")

	require.NotEmpty(t, zone.Signatures)
	assert.WithinDuration(t, time.Unix(int64(expiry), 0), zone.Signatures[0].Expiration, time.Second)

	assert.True(t, zone.NSEC3)
	assert.True(t, zone.AuthenticatedData)
	assert.True(t, zone.Signed())
}

// TestFetchDNSSECZoneDetectsAStaleDS covers the outage case: the parent's
// digest no longer matches the key the zone publishes, so validating resolvers
// return SERVFAIL for every name in it.
func TestFetchDNSSECZoneDetectsAStaleDS(t *testing.T) {
	key := signingKey(t, "stale.test")
	stale := key.ToDS(dns.SHA256)
	// The signing key is generated afresh each run, so the digest differs
	// every time. Overwriting the first byte with a fixed value would be a
	// no-op on the roughly 1 run in 256 whose digest already starts with it,
	// leaving a valid DS and failing the test. Deriving the replacement from
	// the current value guarantees a change.
	if strings.HasPrefix(stale.Digest, "0") {
		stale.Digest = "1" + stale.Digest[1:]
	} else {
		stale.Digest = "0" + stale.Digest[1:]
	}
	require.NotEqual(t, key.ToDS(dns.SHA256).Digest, stale.Digest,
		"the DS must actually be corrupted for this test to mean anything")

	addr, stop := serveZone(t, "stale.test", zoneOptions{key: key, ds: stale})
	defer stop()

	zone, err := scanner.FetchDNSSECZoneWithServer(context.Background(), testResolver, "stale.test", addr)
	require.NoError(t, err)

	require.Len(t, zone.DS, 1)
	assert.True(t, zone.DS[0].DigestMismatch)
}

// TestFetchDNSSECZoneIslandOfTrust covers a signed zone with no delegation from
// the parent, which looks healthy to every check that only asks for DNSKEY.
func TestFetchDNSSECZoneIslandOfTrust(t *testing.T) {
	key := signingKey(t, "island.test")

	addr, stop := serveZone(t, "island.test", zoneOptions{key: key})
	defer stop()

	zone, err := scanner.FetchDNSSECZoneWithServer(context.Background(), testResolver, "island.test", addr)
	require.NoError(t, err)

	assert.NotEmpty(t, zone.Keys)
	assert.Empty(t, zone.DS)
	assert.True(t, zone.Signed())
}

func TestFetchDNSSECZoneUnsignedZone(t *testing.T) {
	addr, stop := serveZone(t, "plain.test", zoneOptions{})
	defer stop()

	zone, err := scanner.FetchDNSSECZoneWithServer(context.Background(), testResolver, "plain.test", addr)
	require.NoError(t, err)

	assert.False(t, zone.Signed())
	assert.False(t, zone.AuthenticatedData)
}

func TestFetchDNSSECZoneDenialOfExistence(t *testing.T) {
	tests := map[string]struct {
		opts            zoneOptions
		nsec, nsec3     bool
		wantSynthesised bool
		wantIterations  int
	}{
		"NSEC-only zone": {
			opts: zoneOptions{nsec: true}, nsec: true,
		},
		// Several large providers answer every denial with an NSEC covering
		// only the queried name. The chain cannot be walked, so reporting it
		// as enumerable would be simply wrong.
		"synthesised NSEC is recognised": {
			opts: zoneOptions{nsec: true, synthesisedNSEC: true},
			nsec: true, wantSynthesised: true,
		},
		"NSEC3 with extra iterations": {
			opts:  zoneOptions{nsec3: true, nsec3Iterations: 12},
			nsec3: true, wantIterations: 12,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key := signingKey(t, "denial.test")
			tc.opts.key = key

			addr, stop := serveZone(t, "denial.test", tc.opts)
			defer stop()

			zone, err := scanner.FetchDNSSECZoneWithServer(context.Background(), testResolver, "denial.test", addr)
			require.NoError(t, err)

			assert.Equal(t, tc.nsec, zone.NSEC)
			assert.Equal(t, tc.nsec3, zone.NSEC3)
			assert.Equal(t, tc.wantSynthesised, zone.NSECSynthesised)
			assert.Equal(t, tc.wantIterations, zone.NSEC3Iterations)
		})
	}
}
