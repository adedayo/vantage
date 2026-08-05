package netattr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateCache points the cache at a temporary directory, so a test never
// reads or writes the developer's real cache.
func isolateCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// os.UserCacheDir consults different variables per platform.
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("LocalAppData", filepath.Join(dir, "appdata"))
	return dir
}

func TestCachePathStaysInsideTheCacheDirectory(t *testing.T) {
	isolateCache(t)

	dir, err := CacheDir()
	require.NoError(t, err)

	// A URL carrying separators and a query string must not be able to place a
	// file outside the cache directory.
	path, err := cachePath("https://example.com/../../etc/passwd?a=../b")
	require.NoError(t, err)

	assert.Equal(t, dir, filepath.Dir(path))
	assert.Equal(t, ".cache", filepath.Ext(path))
}

func TestCachePathIsStablePerURLAndDistinctAcrossURLs(t *testing.T) {
	isolateCache(t)

	first, err := cachePath("https://example.com/a")
	require.NoError(t, err)
	again, err := cachePath("https://example.com/a")
	require.NoError(t, err)
	other, err := cachePath("https://example.com/b")
	require.NoError(t, err)

	assert.Equal(t, first, again, "the same URL must resolve to the same entry")
	assert.NotEqual(t, first, other, "different URLs must not collide")
}

func TestFetchCachedStoresAndThenReusesWithoutRefetching(t *testing.T) {
	isolateCache(t)

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte("ranges"))
	}))
	defer server.Close()

	data, at, err := fetchCached(context.Background(), &Loader{}, server.URL)
	require.NoError(t, err)
	assert.Equal(t, []byte("ranges"), data)
	assert.WithinDuration(t, time.Now(), at, time.Minute)
	assert.Equal(t, 1, requests)

	// The second call must be served from disk. Pulling several megabytes from
	// four operators on every run is the inconsiderate behaviour spec 012
	// requires this tool to avoid.
	data, _, err = fetchCached(context.Background(), &Loader{}, server.URL)
	require.NoError(t, err)
	assert.Equal(t, []byte("ranges"), data)
	assert.Equal(t, 1, requests, "a fresh cache entry must not be refetched")
}

func TestFetchCachedRefetchesOnceTheEntryIsStale(t *testing.T) {
	isolateCache(t)

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte("fresh"))
	}))
	defer server.Close()

	_, _, err := fetchCached(context.Background(), &Loader{}, server.URL)
	require.NoError(t, err)

	path, err := cachePath(server.URL)
	require.NoError(t, err)
	old := time.Now().Add(-CacheTTL - time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))

	data, at, err := fetchCached(context.Background(), &Loader{}, server.URL)
	require.NoError(t, err)
	assert.Equal(t, []byte("fresh"), data)
	assert.Equal(t, 2, requests, "a stale entry must be refetched")
	assert.WithinDuration(t, time.Now(), at, time.Minute)
}

// An operator's endpoint being down must not silently reclassify every host as
// unattributed, which would remove findings that were correct yesterday.
func TestFetchCachedFallsBackToStaleDataWhenTheSourceIsUnreachable(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("last week"))
	}))

	_, _, err := fetchCached(context.Background(), &Loader{}, server.URL)
	require.NoError(t, err)

	path, err := cachePath(server.URL)
	require.NoError(t, err)
	old := time.Now().Add(-CacheTTL - 48*time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))

	server.Close() // the operator's endpoint is now unreachable

	data, at, err := fetchCached(context.Background(), &Loader{}, server.URL)
	require.NoError(t, err)
	assert.Equal(t, []byte("last week"), data)
	// The age must be reported truthfully, so the caller can disclose it
	// rather than presenting week-old data as current.
	assert.WithinDuration(t, old, at, time.Minute)
	assert.Greater(t, time.Since(at), CacheTTL)
}

func TestFetchCachedFailsWhenUnreachableWithNoCacheEntry(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	_, _, err := fetchCached(context.Background(), &Loader{}, url)
	// No data and no cache is the one case that must fail: inventing an empty
	// range set would attribute nothing while looking like a successful load.
	require.Error(t, err)
}

func TestFetchRejectsAnErrorStatus(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("down for maintenance"))
	}))
	defer server.Close()

	_, _, err := fetchCached(context.Background(), &Loader{}, server.URL)
	require.Error(t, err)
	// The body of an error response must never be parsed as ranges.
	assert.Contains(t, err.Error(), "503")
}

func TestFetchCachedHonoursContextCancellation(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte("too late"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _, err := fetchCached(ctx, nil, server.URL)
	require.Error(t, err)
}

// A run interrupted mid-write must not leave a truncated file that parses to a
// partial range set, which would attribute some addresses and silently miss
// others.
func TestWriteCacheIsAtomicAndLeavesNoTemporaryFile(t *testing.T) {
	isolateCache(t)

	path, err := cachePath("https://example.com/ranges")
	require.NoError(t, err)
	require.NoError(t, writeCache(path, []byte("payload")))

	data, _, err := readIfFresh(path, CacheTTL)
	require.NoError(t, err)
	assert.Equal(t, []byte("payload"), data)

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotEqual(t, ".tmp", filepath.Ext(e.Name()), "no temporary file should survive")
	}
}

func TestReadIfFreshRejectsAStaleEntryButZeroTTLAcceptsIt(t *testing.T) {
	isolateCache(t)

	path, err := cachePath("https://example.com/ranges")
	require.NoError(t, err)
	require.NoError(t, writeCache(path, []byte("payload")))

	old := time.Now().Add(-CacheTTL - time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))

	_, _, err = readIfFresh(path, CacheTTL)
	assert.Error(t, err, "an entry older than the TTL is not fresh")

	// A zero TTL is how the stale fallback is expressed.
	data, at, err := readIfFresh(path, 0)
	require.NoError(t, err)
	assert.Equal(t, []byte("payload"), data)
	assert.WithinDuration(t, old, at, time.Minute)
}

func TestReadIfFreshReportsAMissingEntry(t *testing.T) {
	isolateCache(t)

	path, err := cachePath("https://example.com/never-fetched")
	require.NoError(t, err)

	_, _, err = readIfFresh(path, CacheTTL)
	assert.Error(t, err)
}
