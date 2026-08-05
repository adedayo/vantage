package netattr

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withSources substitutes the published range list for the duration of a test.
func withSources(t *testing.T, sources ...providerSource) {
	t.Helper()
	original := providerSources
	providerSources = sources
	t.Cleanup(func() {
		providerSources = original
	})
}

// source builds one entry of the published range list, with the endpoints
// tried in the order given.
func source(name string, endpoints ...endpoint) providerSource {
	return providerSource{name: name, endpoints: endpoints}
}

// at builds one endpoint.
func at(url string, parse func([]byte) ([]ProviderRange, error)) endpoint {
	return endpoint{url: url, parse: parse}
}

func TestLoadCollectsRangesAndReportsCompleteCoverage(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("52.0.0.0/8\n"))
	}))
	defer server.Close()

	withSources(t, source("Example Cloud", at(server.URL, parsePlainList)))

	set, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err)

	assert.True(t, set.Complete())
	assert.Empty(t, set.Stale)
	require.Len(t, set.Providers, 1)
	assert.Equal(t, "Example Cloud", set.Providers[0].Name)

	got := set.Lookup(netip.MustParseAddr("52.1.2.3"))
	assert.Equal(t, "Example Cloud", got.Provider)
}

// The dangerous case: one source fails and the rest succeed. Load returns no
// error, so without Failed the run would continue with a silent coverage hole
// and SURF-NET-001 would stop firing for that operator.
func TestLoadReportsPartialFailureWithoutFailingTheRun(t *testing.T) {
	isolateCache(t)

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer good.Close()

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	withSources(t,
		source("Good Cloud", at(good.URL, parsePlainList)),
		source("Broken Cloud", at(bad.URL, parsePlainList)),
	)

	set, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err, "one failed source must not fail the whole load")

	assert.False(t, set.Complete())
	require.Len(t, set.Failed, 1)
	assert.Contains(t, set.Failed[0], "Broken Cloud")
	assert.Len(t, set.Providers, 1)
}

// A parse failure is a coverage gap exactly as a fetch failure is: the operator
// changed their format and this tool no longer understands it.
func TestLoadTreatsAnUnparseableSourceAsAFailure(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"unexpected": "shape"}`))
	}))
	defer server.Close()

	withSources(t, source("Reshaped Cloud", at(server.URL, func([]byte) ([]ProviderRange, error) {
		return nil, fmt.Errorf("unrecognised format")
	})))

	_, err := NewLoader(nil, nil).Load(context.Background())
	require.Error(t, err, "no usable provider means the check cannot proceed")
	assert.Contains(t, err.Error(), "Reshaped Cloud")
	assert.Contains(t, err.Error(), "unrecognised format")
}

func TestLoadFailsWhenEverySourceIsUnavailable(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	withSources(t, source("Example Cloud", at(url, parsePlainList)))

	_, err := NewLoader(nil, nil).Load(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no cloud provider ranges could be retrieved")
}

// Serving week-old data is defensible; doing so without saying is not.
func TestLoadReportsStaleDataWhenTheSourceCannotBeRefreshed(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	url := server.URL
	withSources(t, source("Example Cloud", at(url, parsePlainList)))

	// Populate the cache, age it beyond the TTL, then take the source away.
	_, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err)

	path, err := cachePath(url)
	require.NoError(t, err)
	old := time.Now().Add(-CacheTTL - 48*time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))
	server.Close()

	set, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err)

	// Coverage is not incomplete — the data is usable — but it was not
	// refreshed, and a reader comparing two runs deserves to know.
	assert.True(t, set.Complete())
	require.Len(t, set.Stale, 1)
	assert.Contains(t, set.Stale[0], "Example Cloud")
	assert.Contains(t, set.Stale[0], "cached")
	assert.Len(t, set.Providers, 1)
}

// Auditing a portfolio must pay for the download once, not once per domain.
func TestLoadMemoisesForTheProcess(t *testing.T) {
	isolateCache(t)

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	withSources(t, source("Example Cloud", at(server.URL, parsePlainList)))

	for range 3 {
		_, err := NewLoader(nil, nil).Load(context.Background())
		require.NoError(t, err)
	}
	assert.Equal(t, 1, requests)
}

// Two publications for one operator, as Cloudflare's separate v4 and v6 lists
// are, must merge rather than appear as two providers.
func TestLoadMergesSourcesSharingAProviderName(t *testing.T) {
	isolateCache(t)

	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("52.0.0.0/8\n"))
	}))
	defer v4.Close()
	v6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("2606:4700::/32\n"))
	}))
	defer v6.Close()

	withSources(t,
		source("Example Cloud", at(v4.URL, parsePlainList)),
		source("Example Cloud", at(v6.URL, parsePlainList)),
	)

	set, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err)

	require.Len(t, set.Providers, 1, "one operator must not appear twice")
	assert.Equal(t, "Example Cloud", set.Lookup(netip.MustParseAddr("52.1.2.3")).Provider)
	assert.Equal(t, "Example Cloud", set.Lookup(netip.MustParseAddr("2606:4700::1")).Provider)
}

// Special-purpose space short-circuits attribution: an operator cannot announce
// RFC 1918 or documentation space, and a provider file claiming otherwise must
// not override the registry.
func TestLookupPrefersSpecialPurposeSpaceOverAProviderClaim(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	withSources(t, source("Confused Cloud", at(server.URL, parsePlainList)))

	set, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err)

	got := set.Lookup(netip.MustParseAddr("203.0.113.9"))
	require.NotNil(t, got.Special)
	assert.Empty(t, got.Provider)
}

// A published URL can be withdrawn or moved. Falling back to an equivalent
// endpoint keeps attribution working; without it one operator's bad afternoon
// removes a whole provider's coverage.
func TestLoadFallsBackToTheNextEndpoint(t *testing.T) {
	isolateCache(t)

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer primary.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("52.0.0.0/8\n"))
	}))
	defer fallback.Close()

	withSources(t, source("Example Cloud",
		at(primary.URL, parsePlainList),
		at(fallback.URL, parsePlainList),
	))

	set, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err)

	assert.True(t, set.Complete(), "a working fallback means coverage is not incomplete")
	assert.Equal(t, "Example Cloud", set.Lookup(netip.MustParseAddr("52.1.2.3")).Provider)

	// The provenance must name the endpoint actually used, not the preferred
	// one, or a reader cannot tell which data produced the attribution.
	require.Len(t, set.Provenance, 1)
	assert.Equal(t, fallback.URL, set.Provenance[0].URL)
}

// A fallback must not be consulted when the preferred endpoint answers: each
// call is traffic to somebody else's free service.
func TestLoadDoesNotUseAFallbackWhenThePrimaryAnswers(t *testing.T) {
	isolateCache(t)

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("52.0.0.0/8\n"))
	}))
	defer primary.Close()

	var fallbackCalls int
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls++
		_, _ = w.Write([]byte("198.51.100.0/24\n"))
	}))
	defer fallback.Close()

	withSources(t, source("Example Cloud",
		at(primary.URL, parsePlainList),
		at(fallback.URL, parsePlainList),
	))

	_, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err)
	assert.Zero(t, fallbackCalls)
}

// A parse failure must move on to the fallback exactly as an unreachable
// endpoint does: an operator that changed format is as unusable as one down.
func TestLoadFallsBackWhenThePrimaryCannotBeParsed(t *testing.T) {
	isolateCache(t)

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not a prefix list at all"))
	}))
	defer primary.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("52.0.0.0/8\n"))
	}))
	defer fallback.Close()

	withSources(t, source("Example Cloud",
		at(primary.URL, parsePlainList),
		at(fallback.URL, parsePlainList),
	))

	set, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err)
	assert.True(t, set.Complete())
	assert.Equal(t, "Example Cloud", set.Lookup(netip.MustParseAddr("52.1.2.3")).Provider)
}

// When every endpoint fails, each failure is named. A caller told only about
// the last would investigate the wrong endpoint.
func TestLoadNamesEveryEndpointFailure(t *testing.T) {
	isolateCache(t)

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer second.Close()

	withSources(t, source("Example Cloud",
		at(first.URL, parsePlainList),
		at(second.URL, parsePlainList),
	))

	set, err := NewLoader(nil, nil).Load(context.Background())
	require.Error(t, err)
	require.Len(t, set.Failed, 1)
	assert.Contains(t, set.Failed[0], "502")
	assert.Contains(t, set.Failed[0], "404")
}

func TestLoadRecordsProvenanceForEverySource(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("52.0.0.0/8\n"))
	}))
	defer server.Close()

	withSources(t, source("Example Cloud", at(server.URL, parsePlainList)))

	set, err := NewLoader(nil, nil).Load(context.Background())
	require.NoError(t, err)

	require.Len(t, set.Provenance, 1)
	assert.Equal(t, "Example Cloud", set.Provenance[0].Provider)
	assert.Equal(t, server.URL, set.Provenance[0].URL)
	assert.WithinDuration(t, time.Now(), set.Provenance[0].Fetched, time.Minute)
}

func TestParseCloudflareAPISplitsTheFamilies(t *testing.T) {
	body := []byte(`{"success":true,"result":{
		"ipv4_cidrs":["173.245.48.0/20"],
		"ipv6_cidrs":["2400:cb00::/32"]}}`)

	v4, err := parseCloudflareAPIv4(body)
	require.NoError(t, err)
	require.Len(t, v4, 1)
	assert.Equal(t, "173.245.48.0/20", v4[0].Prefix.String())

	// Returning both families from either parser would double-count the ranges
	// when only one plain-text list had failed.
	v6, err := parseCloudflareAPIv6(body)
	require.NoError(t, err)
	require.Len(t, v6, 1)
	assert.Equal(t, "2400:cb00::/32", v6[0].Prefix.String())
}

// The API reports failure in the body with HTTP 200, so the status code alone
// would let an error document parse as an empty range set.
func TestParseCloudflareAPIRejectsAnUnsuccessfulBody(t *testing.T) {
	_, err := parseCloudflareAPIv4([]byte(`{"success":false,"errors":[{"code":1}],"result":null}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reported failure")
}
