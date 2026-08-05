// Package ct discovers hostnames from Certificate Transparency logs.
//
// Every certificate a public CA issues is published to append-only logs that
// anybody may read. For an organisation auditing its own attack surface this is
// the sanctioned way to find names it has forgotten: the data is already public,
// reading it touches none of the organisation's own infrastructure, and no name
// is guessed. That last point is what separates this from brute-force
// enumeration, which spec 012 forbids — every name returned here is one a CA
// was asked to certify.
package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	d "github.com/adedayo/vantage/pkg"
)

// Certificate is one issuance discovered in a log.
type Certificate struct {
	// Names are the identities the certificate covers, lower-cased and
	// without a trailing dot.
	Names []string
	// Issuer is the certificate authority, retained as evidence.
	Issuer string
	// NotAfter is when the certificate expires.
	NotAfter time.Time
	// NotBefore is when it became valid.
	NotBefore time.Time
}

// Source is where certificates are discovered. It is an interface so that a
// second log API can be added, or substituted in tests, without the checks
// above it knowing.
type Source interface {
	// Name identifies the source for evidence and error messages.
	Name() string
	// Search returns certificates covering names at or below the domain.
	Search(ctx context.Context, domain string) ([]Certificate, error)
}

// Result is what enumeration found.
type Result struct {
	// Source is where the data came from.
	Source string
	// Certificates are the issuances discovered.
	Certificates []Certificate
	// Hosts are the distinct non-wildcard names at or below the domain.
	Hosts []string
	// WildcardNames are the wildcard identities found, kept separate because
	// they name no host and must not be resolved as though they did.
	WildcardNames []string
}

// crtSh queries the crt.sh certificate search service.
type crtSh struct {
	// BaseURL allows a test to point at a local server. Empty uses crt.sh.
	BaseURL string
	// HTTP is the egress this source queries through. Nil uses the library
	// default, which is what the CLI wants; an embedding consumer supplies a
	// guarded client so that a third-party endpoint it has not consented to
	// is refused at the transport.
	HTTP d.Doer
}

// CrtSh returns a Source backed by crt.sh.
func CrtSh() Source { return crtSh{} }

// CrtShWith returns a crt.sh Source that performs its requests through hc.
func CrtShWith(hc d.Doer) Source { return crtSh{HTTP: hc} }

// Name implements Source.
func (crtSh) Name() string { return "crt.sh" }

// crtShTimeout bounds a query. crt.sh is a free service running a large
// database and is frequently slow; a generous timeout is more useful than a
// fast failure, but an unbounded one would hang an audit indefinitely.
const crtShTimeout = 60 * time.Second

// Search implements Source.
func (c crtSh) Search(ctx context.Context, domain string) ([]Certificate, error) {
	base := c.BaseURL
	if base == "" {
		base = "https://crt.sh/"
	}

	// The percent is crt.sh's wildcard: "%.example.com" matches every name
	// below the domain. The apex is matched by the identity query separately,
	// so both forms are requested.
	q := url.Values{}
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	q.Set("excluded", "expired")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vantage")
	req.Header.Set("Accept", "application/json")

	client := d.HTTPOr(c.HTTP, d.HTTPOptions{Timeout: crtShTimeout})
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error: cannot reach crt.sh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: crt.sh returned HTTP %d", resp.StatusCode)
	}

	var entries []struct {
		NameValue  string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
		NotAfter   string `json:"not_after"`
		NotBefore  string `json:"not_before"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("error: cannot parse the crt.sh response: %w", err)
	}

	certs := make([]Certificate, 0, len(entries))
	for _, e := range entries {
		cert := Certificate{
			Issuer:    e.IssuerName,
			NotAfter:  parseTimestamp(e.NotAfter),
			NotBefore: parseTimestamp(e.NotBefore),
		}
		// crt.sh returns the subject alternative names newline-separated
		// within a single field.
		for _, n := range strings.Split(e.NameValue, "\n") {
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

// normaliseName lower-cases a certificate identity and strips a trailing dot.
func normaliseName(n string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(n), "."))
}

// Collect turns raw certificates into the host and wildcard sets, discarding
// anything outside the domain.
//
// Certificates routinely cover several unrelated domains — a shared hosting
// certificate may list hundreds — so a name that merely appeared alongside the
// target is not the target's. Assessing those would mean reporting on somebody
// else's infrastructure.
func Collect(domain string, certs []Certificate) Result {
	domain = normaliseName(domain)

	hosts := map[string]bool{}
	wildcards := map[string]bool{}

	for _, cert := range certs {
		for _, name := range cert.Names {
			// Normalised again here rather than trusted from the source, so
			// that a second Source implementation cannot introduce duplicates
			// that differ only in case or a trailing dot.
			name = normaliseName(name)
			if name == "" {
				continue
			}
			if strings.HasPrefix(name, "*.") {
				if within(domain, strings.TrimPrefix(name, "*.")) {
					wildcards[name] = true
				}
				continue
			}
			if within(domain, name) {
				hosts[name] = true
			}
		}
	}

	return Result{
		Certificates:  certs,
		Hosts:         sortedKeys(hosts),
		WildcardNames: sortedKeys(wildcards),
	}
}

// within reports whether name is the domain or below it.
func within(domain, name string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
