package audit_test

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/audit"
)

// The most serious rule in this check is decided from the embedded IANA
// registries, so it works with egress disabled — and that is the configuration
// verified here, because it is the one a cautious operator chooses and the one
// in which a silent check would do the most harm.
func TestNetworkCheckDetectsPrivateAddressLeakage(t *testing.T) {
	zoneClient := startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]

		if q.Name == "intranet.example.test." && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 300},
				A: net.ParseIP("10.1.2.3"),
			})
		}
		_ = w.WriteMsg(m)
	})

	check, ok := audit.Lookup("net")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain:    "example.test",
		Cache:     audit.NewCache(zoneClient),
		Hosts:     []string{"intranet.example.test"},
		NoNetwork: true,
	})
	require.NoError(t, err)

	var ids []string
	for _, f := range out.Findings {
		ids = append(ids, f.ID)
	}
	assert.Contains(t, ids, "SURF-NET-002")
}

// The converse: a resolver that answers nothing must produce no findings. An
// address that was never retrieved cannot be attributed, and inventing a
// verdict for it would be the defect this project has met most often.
func TestNetworkCheckIsSilentWhenNothingResolves(t *testing.T) {
	zoneClient := startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})

	check, ok := audit.Lookup("net")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain:    "example.test",
		Cache:     audit.NewCache(zoneClient),
		Hosts:     []string{"intranet.example.test"},
		NoNetwork: true,
	})
	require.NoError(t, err)
	assert.Empty(t, out.Findings)
}

// An ordinary public address with no provider ranges loaded must yield nothing.
// Under --no-network no operator's ranges are available, so every address is
// unattributed — and "unattributed" must never be rendered as a finding.
func TestNetworkCheckMakesNoClaimsWithoutProviderRanges(t *testing.T) {
	zoneClient := startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]

		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 300},
				A: net.ParseIP("93.184.216.34"),
			})
		}
		_ = w.WriteMsg(m)
	})

	check, ok := audit.Lookup("net")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain:    "example.test",
		Cache:     audit.NewCache(zoneClient),
		NoNetwork: true,
	})
	require.NoError(t, err)
	assert.Empty(t, out.Findings)
	// The address is still recorded, so a reader sees what was assessed rather
	// than only what was wrong.
	assert.NotEmpty(t, out.Records)
}
