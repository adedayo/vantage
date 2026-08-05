package netattr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	d "github.com/adedayo/vantage/pkg"
)

// CacheTTL is how long a downloaded range file is reused.
//
// Seven days is a compromise between accuracy and courtesy. Operators revise
// these files daily, but a prefix that moved yesterday is still almost always
// announced by the same operator, so the cost of week-old data is a slightly
// stale region rather than a wrong provider. The benefit is that auditing a
// portfolio does not pull several megabytes from four operators every run.
const CacheTTL = 7 * 24 * time.Hour

// maxRangeFileSize bounds a download. The largest of these publications is a
// few megabytes; anything far larger is a mistake or a hostile response, and
// reading it in full would let a third party exhaust this process's memory.
const maxRangeFileSize = 64 << 20

// CacheDir returns the directory range files are cached in.
func CacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("error: cannot determine the user cache directory: %w", err)
	}
	return filepath.Join(base, "vantage", "netattr"), nil
}

// fetchCached returns a range file, from disk when it is fresh enough and from
// the network otherwise.
//
// A stale cache entry is preferred to a failed fetch. If an operator's endpoint
// is down, attributing addresses from last week's data is far better than
// attributing none — the alternative would silently reclassify every host as
// unattributed and remove findings that were correct yesterday.
//
// The returned time is when the data was obtained, so a caller can disclose the
// age of what it is reasoning from. Serving week-old data is defensible; doing
// so without saying is not.
func fetchCached(ctx context.Context, l *Loader, url string) ([]byte, time.Time, error) {
	// A nil loader means "no store, default egress" rather than a programming
	// error, so that the on-disk cache path remains usable without one.
	if l == nil {
		l = &Loader{}
	}
	ttl := l.ttl()
	path, pathErr := cachePath(url)

	// The injected store is consulted first. An embedding consumer that
	// supplies one is sharing a download across many assessments, and going
	// to its own on-disk cache instead would defeat that.
	if l.Store != nil {
		if data, at, ok := l.Store.Get(ctx, url); ok && time.Since(at) <= ttl {
			return data, at, nil
		}
	} else if pathErr == nil {
		if data, at, err := readIfFresh(path, ttl); err == nil {
			return data, at, nil
		}
	}

	data, fetchErr := fetch(ctx, l.HTTP, url)
	if fetchErr != nil {
		// Stale-on-unreachable: older data beats none, provided its age is
		// disclosed. The caller reports it under Set.Stale.
		if l.Store != nil {
			if stale, at, ok := l.Store.Get(ctx, url); ok {
				return stale, at, nil
			}
		} else if pathErr == nil {
			if stale, at, err := readIfFresh(path, 0); err == nil {
				return stale, at, nil
			}
		}
		return nil, time.Time{}, fetchErr
	}

	now := time.Now().UTC()
	// A cache that cannot be written is not an error worth failing on: the
	// data is in hand and the only cost is fetching it again next time.
	if l.Store != nil {
		_ = l.Store.Put(ctx, url, data, now)
	} else if pathErr == nil {
		_ = writeCache(path, data)
	}
	return data, now, nil
}

// readIfFresh returns the cached file, and when it was written, if it is
// younger than ttl. A ttl of zero accepts any age, which is how the stale
// fallback is expressed.
func readIfFresh(path string, ttl time.Duration) ([]byte, time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	if ttl > 0 && time.Since(info.ModTime()) > ttl {
		return nil, time.Time{}, fmt.Errorf("cache entry is stale")
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is derived from a hash of a constant URL
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, info.ModTime().UTC(), nil
}

func writeCache(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// Written to a temporary file and renamed, so a run interrupted mid-write
	// cannot leave a truncated file that parses to a partial range set.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cachePath names the cache entry after a hash of the URL, so that a URL
// containing path separators or query strings cannot escape the cache
// directory.
func cachePath(url string) (string, error) {
	dir, err := CacheDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".cache"), nil
}

// rangeFetchTimeout bounds a single provider range download. The files run to
// several megabytes, so the bound is generous; an unbounded fetch would let one
// unresponsive operator stall an audit indefinitely.
const rangeFetchTimeout = 30 * time.Second

func fetch(ctx context.Context, hc d.Doer, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vantage")

	resp, err := d.HTTPOr(hc, d.HTTPOptions{Timeout: rangeFetchTimeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: %s returned HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxRangeFileSize))
}
