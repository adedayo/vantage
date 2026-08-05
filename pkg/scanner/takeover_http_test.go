package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A service's claim-me page is the strongest evidence of a takeover available,
// so the fingerprint must be found in the body it actually serves.
func TestCorroborateTakeoverFindsClaimMePage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>There isn't a GitHub Pages site here.</body></html>"))
	}))
	defer srv.Close()

	res := CorroborateTakeover(context.Background(), nil, hostOf(srv.URL),
		[]string{"There isn't a GitHub Pages site here."})

	assert.True(t, res.Fetched)
	assert.True(t, res.Unclaimed)
	assert.Equal(t, "There isn't a GitHub Pages site here.", res.Matched)
	assert.Equal(t, http.StatusNotFound, res.Status)
}

// Providers change the capitalisation of their error pages without changing
// their meaning; a fingerprint that stopped matching would turn a Critical
// finding into silence.
func TestCorroborateTakeoverMatchesCaseInsensitively(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("NoSuchBucket"))
	}))
	defer srv.Close()

	res := CorroborateTakeover(context.Background(), nil, hostOf(srv.URL), []string{"nosuchbucket"})
	assert.True(t, res.Unclaimed)
}

// A live site must be reported as fetched-and-in-use, which is what lets the
// caller suppress the weaker unverified finding.
func TestCorroborateTakeoverLiveSiteIsNotUnclaimed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Welcome to the documentation.</body></html>"))
	}))
	defer srv.Close()

	res := CorroborateTakeover(context.Background(), nil, hostOf(srv.URL), []string{"NoSuchBucket"})
	assert.True(t, res.Fetched)
	assert.False(t, res.Unclaimed)
}

// The converse of the above, and the one that matters most: a request that
// never completed must leave Fetched false. A caller that read "no match" from
// a failed request would conclude the name is in use without having asked.
func TestCorroborateTakeoverUnreachableHostEstablishesNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Reserved for documentation use (RFC 5737) and therefore never routable.
	res := CorroborateTakeover(ctx, nil, "192.0.2.1:1", []string{"NoSuchBucket"})
	assert.False(t, res.Fetched)
	assert.False(t, res.Unclaimed)
	assert.NotEmpty(t, res.Error)
}

// A service with no declared body fingerprints cannot be corroborated at all.
// Returning "fetched, no match" would answer a question that was never put.
func TestCorroborateTakeoverWithoutFingerprintsDoesNotFetch(t *testing.T) {
	res := CorroborateTakeover(context.Background(), nil, "example.com", nil)
	assert.False(t, res.Fetched)
	assert.NotEmpty(t, res.Error)
}

// A redirect off the host would have us fingerprinting somebody else's page
// and attributing the verdict to this name.
func TestCorroborateTakeoverDoesNotFollowRedirects(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("NoSuchBucket"))
	}))
	defer elsewhere.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer srv.Close()

	res := CorroborateTakeover(context.Background(), nil, hostOf(srv.URL), []string{"NoSuchBucket"})
	require.True(t, res.Fetched)
	assert.False(t, res.Unclaimed)
	assert.Equal(t, http.StatusFound, res.Status)
}

// A hostile target must not be able to make this process read an unbounded
// response into memory.
func TestCorroborateTakeoverBoundsTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", takeoverBodyLimit+4096)))
		_, _ = w.Write([]byte("NoSuchBucket"))
	}))
	defer srv.Close()

	res := CorroborateTakeover(context.Background(), nil, hostOf(srv.URL), []string{"NoSuchBucket"})
	assert.True(t, res.Fetched)
	assert.False(t, res.Unclaimed, "the fingerprint past the read limit must not be matched")
}

func hostOf(rawURL string) string {
	return strings.TrimPrefix(rawURL, "http://")
}
