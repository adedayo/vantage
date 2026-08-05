package vantage

import (
	"crypto/tls"
	"net/http"
	"time"
)

// Doer is the HTTP egress every check performs its requests through.
//
// It is an interface, and *http.Client satisfies it, so that an embedding
// consumer can interpose its own policy on the way out. Trawl wraps this in a
// scope guard: a request for a host the operator has not authorised is refused
// at the transport, so a target outside scope emits no packet even if some
// check asks for one. That guarantee cannot be made if a check is free to
// construct its own client, which is why nothing in this library does so
// outside of NewHTTPClient.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPOptions configures the default client.
type HTTPOptions struct {
	// Timeout bounds a single request. Zero means no client-level bound, in
	// which case only the request context limits it.
	Timeout time.Duration
	// FollowRedirects permits the client to follow a redirect. It is off by
	// default: a redirect off the host would have us attributing somebody
	// else's response to the name under assessment.
	FollowRedirects bool
}

// NewHTTPClient builds the standard client, and is the only place in this
// library that constructs one.
//
// The defaults are deliberately restrictive. TLS 1.2 is the floor; keep-alives
// are disabled so that a scan of many hosts does not hold connections open
// against infrastructure that belongs to someone else; and redirects are not
// followed, so a response is always attributable to the name that was asked.
func NewHTTPClient(opts HTTPOptions) *http.Client {
	c := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
	}
	if !opts.FollowRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

// HTTPOr returns the supplied Doer, or a default client when it is nil.
//
// Callers within this library must route every request through this, so that
// there is exactly one path by which HTTP egress can occur and exactly one
// place a consumer has to interpose on to control it.
func HTTPOr(d Doer, opts HTTPOptions) Doer {
	if d != nil {
		return d
	}
	return NewHTTPClient(opts)
}
