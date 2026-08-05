package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	d "github.com/adedayo/vantage/pkg"
)

// takeoverHTTPTimeout bounds a single corroboration request. An unclaimed name
// often points at infrastructure that black-holes traffic, so the timeout is
// what stops one dead host stalling an audit.
const takeoverHTTPTimeout = 10 * time.Second

// takeoverBodyLimit bounds how much of a response is read. Claim-me pages are
// small; anything larger is a live service, and reading it in full would let a
// hostile target consume this process's memory.
const takeoverBodyLimit = 64 << 10

// TakeoverCorroboration is the result of asking a host's web server whether the
// name is unclaimed.
type TakeoverCorroboration struct {
	// Fetched reports that some response was obtained. When false the
	// corroboration established nothing and the caller must not read the
	// absence of a match as evidence that the name is in use.
	Fetched bool
	// Unclaimed reports that the response body carried one of the service's
	// claim-me fingerprints.
	Unclaimed bool
	// Matched is the fingerprint fragment that was found, retained as evidence
	// so a reader can see what the verdict rests on.
	Matched string
	// URL is the address that produced the response.
	URL string
	// Status is the HTTP status code returned.
	Status int
	// Error describes why no response was obtained.
	Error string
}

// CorroborateTakeover fetches a host over HTTP and looks for the fingerprints
// that a service shows on a name nobody has claimed.
//
// This is a plain unauthenticated GET and nothing else. Spec 012 is explicit
// that the tool detects and never exploits: no attempt is made to register the
// name, no credentials are offered, and the response is read only far enough to
// match a fingerprint.
//
// HTTPS is tried first and plain HTTP second. The fallback matters because an
// unclaimed name usually has no valid certificate for itself — that is a
// symptom of the very condition being checked — so requiring a good handshake
// would miss most true positives. The fallback is to unencrypted HTTP rather
// than to HTTPS with verification disabled, because the request carries nothing
// worth protecting and pretending to have validated a certificate would be
// worse than plainly not using one.
func CorroborateTakeover(ctx context.Context, hc d.Doer, host string, fingerprints []string) TakeoverCorroboration {
	if len(fingerprints) == 0 {
		// Nothing to look for. Reporting this as "fetched, no match" would let
		// the caller conclude the name is in use on the strength of a question
		// that was never asked.
		return TakeoverCorroboration{Error: "no HTTP fingerprints declared for this service"}
	}

	// Redirects are not followed: a redirect off the host would have us
	// fingerprinting somebody else's page and attributing the verdict here.
	client := d.HTTPOr(hc, d.HTTPOptions{Timeout: takeoverHTTPTimeout})

	var lastErr string
	for _, url := range []string{"https://" + host + "/", "http://" + host + "/"} {
		body, status, err := fetchBody(ctx, client, url)
		if err != nil {
			lastErr = err.Error()
			continue
		}

		result := TakeoverCorroboration{Fetched: true, URL: url, Status: status}
		if match, ok := matchBody(body, fingerprints); ok {
			result.Unclaimed = true
			result.Matched = match
		}
		return result
	}

	return TakeoverCorroboration{Error: lastErr}
}

// fetchBody performs the bounded GET.
func fetchBody(ctx context.Context, client d.Doer, url string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "vantage")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, takeoverBodyLimit))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// matchBody reports which claim-me fragment, if any, the response carried.
//
// Matching is case-insensitive because providers change the capitalisation of
// their error pages without changing their meaning, and a fingerprint that
// stopped matching would turn a Critical finding into silence.
func matchBody(body string, fingerprints []string) (string, bool) {
	lower := strings.ToLower(body)
	for _, f := range fingerprints {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(f)) {
			return f, true
		}
	}
	return "", false
}
