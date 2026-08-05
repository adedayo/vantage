package scanner_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/scanner"
)

// fetchFrom points the fetcher at a test server by rewriting the policy host to
// the server's address. The production path builds the URL from the domain, so
// this exercises everything after URL construction.
func fetchFrom(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Path = path

	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Get(u.String())
	require.NoError(t, err)
	return resp
}

// TestFetchMTASTSPolicyRefusesRedirects is the security-relevant behaviour.
// RFC 8461 forbids following redirects: a sender that accepted a policy from a
// redirected location would let anyone able to intercept the request supply
// their own policy, which is precisely the attack MTA-STS exists to prevent.
func TestFetchMTASTSPolicyRefusesRedirects(t *testing.T) {
	var reachedTarget bool

	target := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			reachedTarget = true
			_, _ = w.Write([]byte("version: STSv1\nmode: enforce\nmx: evil.example\nmax_age: 604800\n"))
		}))
	defer target.Close()

	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
	defer srv.Close()

	resp := fetchFrom(t, srv, "/.well-known/mta-sts.txt")
	defer func() { _ = resp.Body.Close() }()

	assert.GreaterOrEqual(t, resp.StatusCode, 300)
	assert.Less(t, resp.StatusCode, 400)
	assert.False(t, reachedTarget, "the redirect target must not be fetched")
}

// TestFetchMTASTSPolicyRejectsUntrustedCertificate confirms the fetcher does
// not silently accept an unverifiable policy host. httptest serves a
// self-signed certificate, so a default client must refuse it.
func TestFetchMTASTSPolicyRejectsUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("version: STSv1\nmode: enforce\n"))
		}))
	defer srv.Close()

	// A default client, as the fetcher uses — not srv.Client(), which trusts
	// the test certificate.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}}

	resp, err := client.Get(srv.URL + "/.well-known/mta-sts.txt")
	require.Error(t, err, "a self-signed policy host must not be trusted")
	// An error does not guarantee a nil response, and leaking the body would
	// hold the connection open for the rest of the run.
	if resp != nil {
		_ = resp.Body.Close()
	}
}

// TestFetchMTASTSPolicyUnreachableHost covers the common real-world case: the
// TXT record advertises a policy that was never actually published.
func TestFetchMTASTSPolicyUnreachableHost(t *testing.T) {
	// RFC 2606 reserves .invalid, so this cannot resolve.
	policy := scanner.FetchMTASTSPolicy(context.Background(), testResolver, nil, "nonexistent.invalid")

	assert.True(t, policy.Fetched, "an attempt was made, and that must be recorded")
	assert.False(t, policy.Valid)
	assert.NotEmpty(t, policy.Reason)
}

// minimalResolver implements exactly the Resolver interface and nothing more.
//
// This is what an embedding consumer's wrapper looks like — a scope guard, say,
// which has no reason to forward optional methods it was never asked about.
type minimalResolver struct{}

func (minimalResolver) ExchangeFrom(context.Context, string, uint16) (*dns.Msg, string, error) {
	return nil, "", errors.New("error: not found")
}

func (minimalResolver) ExchangeRawFrom(context.Context, string, uint16) (*dns.Msg, string, error) {
	return nil, "", errors.New("error: not found")
}

func (minimalResolver) ExchangeDNSSECRawFrom(context.Context, string, uint16) (*dns.Msg, string, error) {
	return nil, "", errors.New("error: not found")
}

func (minimalResolver) ExchangeWithServer(context.Context, string, string, uint16) (*dns.Msg, error) {
	return nil, errors.New("error: not found")
}

func (minimalResolver) ExchangeDNSSECWithServer(context.Context, string, string, uint16) (*dns.Msg, error) {
	return nil, errors.New("error: not found")
}

func (minimalResolver) Servers() []string { return []string{"guarded"} }

// TestFetchMTASTSPolicyAcceptsAnyResolver is a regression test.
//
// The fetcher used to assert its resolver into an interface carrying
// TotalTimeout, unchecked. That holds for the library's own *Client and panics
// for anything else — so the first embedding consumer to wrap a resolver for
// scope enforcement would have crashed the process, on the one code path whose
// purpose is to be safe to point at somebody else's infrastructure.
func TestFetchMTASTSPolicyAcceptsAnyResolver(t *testing.T) {
	require.NotPanics(t, func() {
		policy := scanner.FetchMTASTSPolicy(
			context.Background(), minimalResolver{}, nil, "nonexistent.invalid")

		assert.True(t, policy.Fetched)
		assert.False(t, policy.Valid)
	}, "a resolver that implements only the documented interface must be enough")
}

// TestFetchMTASTSPolicyBoundsBodySize guards against a policy host returning an
// unbounded response to an auditor that asked a small question.
func TestFetchMTASTSPolicyBoundsBodySize(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n"))
			_, _ = w.Write([]byte(strings.Repeat("x", 1<<20)))
		}))
	defer srv.Close()

	resp := fetchFrom(t, srv, "/.well-known/mta-sts.txt")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestParsePolicyFromServedBody ties the fetch path to the parser, confirming a
// well-formed served policy is understood.
func TestParsePolicyFromServedBody(t *testing.T) {
	body := "version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com\r\nmx: mx2.example.com\r\nmax_age: 604800\r\n"

	policy := analyse.ParseMTASTSPolicy(body)
	require.True(t, policy.Valid)
	assert.Equal(t, "enforce", policy.Mode)
	assert.Equal(t, []string{"mx1.example.com", "mx2.example.com"}, policy.MX)
	assert.Equal(t, 604800, policy.MaxAge)
}
