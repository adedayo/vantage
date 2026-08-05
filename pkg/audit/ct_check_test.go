package audit_test

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/audit"
	"github.com/adedayo/vantage/pkg/ct"
)

// stubSource stands in for a Certificate Transparency log.
type stubSource struct {
	certs []ct.Certificate
	err   error
}

func (stubSource) Name() string { return "stub" }

func (s stubSource) Search(context.Context, string) ([]ct.Certificate, error) {
	return s.certs, s.err
}

// isolateCache points the cache at a temporary directory, so a test neither
// reads the developer's cached results nor writes into them.
func isolateCache(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("LocalAppData", dir)
}

// A certificate for a name that no longer resolves is the condition this check
// exists to find, so it is verified through the whole path: enumeration,
// resolution, judgement, finding.
func TestCTCheckDetectsCertificateForAVanishedHost(t *testing.T) {
	isolateCache(t)
	defer audit.SetCTSource(stubSource{certs: []ct.Certificate{
		{Names: []string{"old.example.test", "www.example.test"}, Issuer: "CN=Test CA"},
	}})()

	zoneClient := startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]

		switch {
		case q.Name == "www.example.test." && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 300},
				A: net.ParseIP("93.184.216.34"),
			})
		case q.Name == "old.example.test.":
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})

	check, ok := audit.Lookup("ct")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain: "example.test",
		Cache:  audit.NewCache(zoneClient),
	})
	require.NoError(t, err)

	var ids []string
	for _, f := range out.Findings {
		ids = append(ids, f.ID)
	}
	assert.Contains(t, ids, "SURF-CT-001")

	// The live name must not also be reported, or the rule would fire on every
	// host an organisation has ever certified.
	assert.Len(t, ids, 1)
}

// The converse. A resolver that establishes nothing must produce no findings:
// SERVFAIL is not evidence that a host has been decommissioned.
func TestCTCheckIsSilentWhenTheResolverFails(t *testing.T) {
	isolateCache(t)
	defer audit.SetCTSource(stubSource{certs: []ct.Certificate{
		{Names: []string{"old.example.test"}, Issuer: "CN=Test CA"},
	}})()

	zoneClient := startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})

	check, ok := audit.Lookup("ct")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain: "example.test",
		Cache:  audit.NewCache(zoneClient),
	})
	require.NoError(t, err)
	assert.Empty(t, out.Findings)
}

// A log service that cannot be reached must fail the check rather than report
// an empty inventory, which would read as "this domain has no certificates".
func TestCTCheckFailsWhenTheLogIsUnreachable(t *testing.T) {
	isolateCache(t)
	defer audit.SetCTSource(stubSource{err: assert.AnError})()

	zoneClient := startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})

	check, ok := audit.Lookup("ct")
	require.True(t, ok)

	_, err := check.Run(context.Background(), audit.Target{
		Domain: "example.test",
		Cache:  audit.NewCache(zoneClient),
	})
	assert.Error(t, err)
}

// Names discovered in certificates must not silently include somebody else's:
// a shared hosting certificate lists many unrelated domains.
func TestCTCheckAssessesOnlyNamesWithinTheDomain(t *testing.T) {
	isolateCache(t)
	defer audit.SetCTSource(stubSource{certs: []ct.Certificate{
		{Names: []string{"old.example.test", "old.someone-else.test"}},
	}})()

	zoneClient := startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})

	check, ok := audit.Lookup("ct")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain: "example.test",
		Cache:  audit.NewCache(zoneClient),
	})
	require.NoError(t, err)

	for _, f := range out.Findings {
		for _, e := range f.Evidence {
			assert.NotContains(t, e.Value, "someone-else.test")
		}
	}
}
