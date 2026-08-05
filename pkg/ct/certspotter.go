package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	d "github.com/adedayo/vantage/pkg"
)

// certSpotter queries the Cert Spotter issuance API.
//
// It is a second source rather than a replacement for crt.sh. Certificate
// Transparency data is only as useful as the availability of whoever serves it,
// and crt.sh — a free service run as a public good — is regularly unreachable.
// A check that reports "could not enumerate" whenever one operator has a bad
// afternoon is a check people turn off.
type certSpotter struct {
	// BaseURL allows a test to point at a local server.
	BaseURL string
	// HTTP is the egress this source queries through. Nil uses the library
	// default.
	HTTP d.Doer
}

// CertSpotter returns a Source backed by the Cert Spotter API.
func CertSpotter() Source { return certSpotter{} }

// CertSpotterWith returns a Cert Spotter Source that performs its requests
// through hc.
func CertSpotterWith(hc d.Doer) Source { return certSpotter{HTTP: hc} }

// Name implements Source.
func (certSpotter) Name() string { return "certspotter" }

const certSpotterTimeout = 30 * time.Second

// Search implements Source.
func (c certSpotter) Search(ctx context.Context, domain string) ([]Certificate, error) {
	base := c.BaseURL
	if base == "" {
		base = "https://api.certspotter.com/v1/issuances"
	}

	q := url.Values{}
	q.Set("domain", domain)
	q.Set("include_subdomains", "true")
	q.Add("expand", "dns_names")
	q.Add("expand", "issuer")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vantage")
	req.Header.Set("Accept", "application/json")

	client := d.HTTPOr(c.HTTP, d.HTTPOptions{Timeout: certSpotterTimeout})
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error: cannot reach the Cert Spotter API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		// The unauthenticated tier is rate-limited. Saying so is far more use
		// than a bare status code, because the remedy is to wait rather than
		// to investigate the domain.
		return nil, fmt.Errorf(
			"error: the Cert Spotter API rate limit was reached; results are cached for %s, so retry later",
			CacheTTL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: the Cert Spotter API returned HTTP %d", resp.StatusCode)
	}

	var entries []struct {
		DNSNames []string `json:"dns_names"`
		Issuer   struct {
			FriendlyName string `json:"friendly_name"`
			Name         string `json:"name"`
		} `json:"issuer"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("error: cannot parse the Cert Spotter response: %w", err)
	}

	certs := make([]Certificate, 0, len(entries))
	for _, e := range entries {
		issuer := e.Issuer.FriendlyName
		if issuer == "" {
			issuer = e.Issuer.Name
		}

		cert := Certificate{
			Issuer:    issuer,
			NotBefore: parseTimestamp(e.NotBefore),
			NotAfter:  parseTimestamp(e.NotAfter),
		}
		for _, n := range e.DNSNames {
			if n = normaliseName(n); n != "" {
				cert.Names = append(cert.Names, n)
			}
		}
		if len(cert.Names) > 0 {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// parseTimestamp reads the timestamp formats these APIs emit. crt.sh omits the
// zone; Cert Spotter uses RFC 3339.
func parseTimestamp(s string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Sources is the ordered set of log services tried.
type Sources []Source

// DefaultSources returns the sources used when none is specified.
//
// Order is significance, not preference: each is tried until one answers. Both
// read the same underlying logs, so the first usable answer is as good as any.
func DefaultSources() Sources { return Sources{CertSpotter(), CrtSh()} }

// DefaultSourcesWith returns the default sources, each querying through hc.
// An embedding consumer uses this so that every CT request passes through the
// transport it controls.
func DefaultSourcesWith(hc d.Doer) Sources {
	return Sources{CertSpotterWith(hc), CrtShWith(hc)}
}

// Name implements Source.
func (s Sources) Name() string {
	names := make([]string, 0, len(s))
	for _, src := range s {
		names = append(names, src.Name())
	}
	return strings.Join(names, " or ")
}

// Search implements Source by trying each source until one succeeds.
//
// Every failure is reported when they all fail. A caller told only about the
// last one would investigate the wrong service, and "CT enumeration failed"
// without saying which service and why is not an actionable statement.
func (s Sources) Search(ctx context.Context, domain string) ([]Certificate, error) {
	var failures []string
	for _, src := range s {
		certs, err := src.Search(ctx, domain)
		if err == nil {
			return certs, nil
		}
		failures = append(failures, src.Name()+": "+strings.TrimPrefix(err.Error(), "error: "))
	}
	return nil, fmt.Errorf("error: no certificate transparency source could be queried (%s)",
		strings.Join(failures, "; "))
}
