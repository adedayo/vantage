package audit_test

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/audit"
	"github.com/adedayo/vantage/pkg/scanner"
)

// startZone runs a mock resolver so that retrieval can be exercised end to end.
//
// The judgement is unit-tested in pkg/analyse; what is verified here is that
// retrieval maps real DNS answers onto it correctly — in particular that
// NXDOMAIN reaches the rules as NXDOMAIN, which is the difference between the
// check working and the check being silent on every domain.
func startZone(t *testing.T, handler func(w dns.ResponseWriter, r *dns.Msg)) vantage.Resolver {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(handler)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return vantage.NewClient(vantage.Config{Servers: []string{pc.LocalAddr().String()}})
}

// A dangling alias to a claimable service is the condition the whole check
// exists for, so it is verified against a resolver rather than only in theory.
func TestTakeoverCheckDetectsDanglingAlias(t *testing.T) {
	zoneClient := startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]

		switch {
		case q.Name == "assets.example.test." && q.Qtype == dns.TypeCNAME:
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME,
					Class: dns.ClassINET, Ttl: 300},
				Target: "abandoned.s3.amazonaws.com.",
			})
		case q.Name == "abandoned.s3.amazonaws.com.":
			// The bucket is gone: the name does not exist.
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})

	check, ok := audit.Lookup("tko")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain: "example.test",
		Cache:  audit.NewCache(zoneClient),
		Hosts:  []string{"assets.example.test"},
	})
	require.NoError(t, err)

	var ids []string
	for _, f := range out.Findings {
		ids = append(ids, f.ID)
	}
	assert.Contains(t, ids, "SURF-TKO-001")
}

// A resolver that fails must not manufacture a Critical finding. This is the
// same defect family that has bitten this project repeatedly: a query that did
// not complete read as a definitive answer.
func TestTakeoverCheckIsSilentWhenTheResolverFails(t *testing.T) {
	zoneClient := startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]

		if q.Name == "assets.example.test." && q.Qtype == dns.TypeCNAME {
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME,
					Class: dns.ClassINET, Ttl: 300},
				Target: "abandoned.s3.amazonaws.com.",
			})
			_ = w.WriteMsg(m)
			return
		}
		// Everything else fails to answer: nothing has been established about
		// the target, so nothing may be concluded about it.
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})

	check, ok := audit.Lookup("tko")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain: "example.test",
		Cache:  audit.NewCache(zoneClient),
		Hosts:  []string{"assets.example.test"},
	})
	require.NoError(t, err)
	assert.Empty(t, out.Findings)
}

// aliasZone serves one host aliased to a claimable service whose target still
// resolves — the case DNS alone cannot judge, and which HTTP corroboration
// exists to settle.
func aliasZone(t *testing.T) vantage.Resolver {
	t.Helper()
	return startZone(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]

		switch {
		case q.Name == "docs.example.test." && q.Qtype == dns.TypeCNAME:
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME,
					Class: dns.ClassINET, Ttl: 300},
				Target: "example.github.io.",
			})
		case q.Name == "example.github.io." && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 300},
				A: net.ParseIP("185.199.108.153"),
			})
		}
		_ = w.WriteMsg(m)
	})
}

// The service reporting the name as unregistered is stronger evidence than any
// DNS answer, and must reach the rules as such.
func TestTakeoverCheckReportsHTTPCorroboration(t *testing.T) {
	zoneClient := aliasZone(t)

	var asked string
	defer audit.SetCorroborator(func(_ context.Context, _ vantage.Doer, host string, _ []string) scanner.TakeoverCorroboration {
		asked = host
		return scanner.TakeoverCorroboration{
			Fetched: true, Unclaimed: true,
			Matched: "There isn't a GitHub Pages site here.",
			URL:     "https://" + host + "/",
		}
	})()

	check, ok := audit.Lookup("tko")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain: "example.test",
		Cache:  audit.NewCache(zoneClient),
		Hosts:  []string{"docs.example.test"},
	})
	require.NoError(t, err)

	// The host is fetched, not the alias target: the verdict is about the name
	// the organisation published.
	assert.Equal(t, "docs.example.test", asked)

	var ids []string
	for _, f := range out.Findings {
		ids = append(ids, f.ID)
	}
	assert.Contains(t, ids, "SURF-TKO-002")
}

// Having looked and found the name in use, the check must not fall back to
// reporting it as unverified.
func TestTakeoverCheckSuppressesUnverifiedWhenTheNameIsInUse(t *testing.T) {
	zoneClient := aliasZone(t)

	defer audit.SetCorroborator(func(_ context.Context, _ vantage.Doer, host string, _ []string) scanner.TakeoverCorroboration {
		return scanner.TakeoverCorroboration{Fetched: true, URL: "https://" + host + "/", Status: 200}
	})()

	check, ok := audit.Lookup("tko")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain: "example.test",
		Cache:  audit.NewCache(zoneClient),
		Hosts:  []string{"docs.example.test"},
	})
	require.NoError(t, err)
	assert.Empty(t, out.Findings)
}

// The converse, and the one that matters: a corroboration request that failed
// established nothing, so the weaker unverified finding must survive. Treating
// a failed fetch as "in use" would silence the check on precisely the hosts
// whose infrastructure has gone away.
func TestTakeoverCheckKeepsUnverifiedWhenCorroborationFails(t *testing.T) {
	zoneClient := aliasZone(t)

	defer audit.SetCorroborator(func(_ context.Context, _ vantage.Doer, _ string, _ []string) scanner.TakeoverCorroboration {
		return scanner.TakeoverCorroboration{Error: "connection refused"}
	})()

	check, ok := audit.Lookup("tko")
	require.True(t, ok)

	out, err := check.Run(context.Background(), audit.Target{
		Domain: "example.test",
		Cache:  audit.NewCache(zoneClient),
		Hosts:  []string{"docs.example.test"},
	})
	require.NoError(t, err)

	var ids []string
	for _, f := range out.Findings {
		ids = append(ids, f.ID)
	}
	assert.Contains(t, ids, "SURF-TKO-003")
}

// --no-network must not send HTTP traffic. A check that quietly egressed after
// being told not to would break the promise the flag exists to make.
func TestTakeoverCheckMakesNoRequestsWithoutNetwork(t *testing.T) {
	zoneClient := aliasZone(t)

	called := false
	defer audit.SetCorroborator(func(_ context.Context, _ vantage.Doer, _ string, _ []string) scanner.TakeoverCorroboration {
		called = true
		return scanner.TakeoverCorroboration{}
	})()

	check, ok := audit.Lookup("tko")
	require.True(t, ok)

	_, err := check.Run(context.Background(), audit.Target{
		Domain:    "example.test",
		Cache:     audit.NewCache(zoneClient),
		Hosts:     []string{"docs.example.test"},
		NoNetwork: true,
	})
	require.NoError(t, err)
	assert.False(t, called)
}
