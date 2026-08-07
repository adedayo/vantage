package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CacheTTL is how long a domain's CT results are reused.
//
// Twenty-four hours reflects what the data is. A certificate issued this
// morning is worth discovering, but not at the cost of querying a free public
// service on every run of an audit somebody may have scripted hourly. crt.sh is
// operated as a public good and this tool must not be the reason it is slow for
// everybody else.
const CacheTTL = 24 * time.Hour

// CacheDir returns the directory CT results are cached in.
func CacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("error: cannot determine the user cache directory: %w", err)
	}
	return filepath.Join(base, "vantage", "ct"), nil
}

// cacheEntry is the on-disk form.
type cacheEntry struct {
	// Source records which log service produced the data, so a cache written
	// by one source is not served to another.
	Source string `json:"source"`
	// Fetched is when the query ran.
	Fetched time.Time `json:"fetched"`
	// Certificates are the discovered issuances.
	Certificates []Certificate `json:"certificates"`
}

// Enumerate searches a source for a domain's certificates, using the cache when
// it is fresh.
//
// A stale entry is served when the source cannot be reached. Yesterday's list
// of names is far more useful than none: the alternative silently narrows every
// downstream check to the hosts the operator happened to name on the command
// line, without saying that is what happened.
func Enumerate(ctx context.Context, src Source, domain string) (Result, error) {
	return EnumerateWith(ctx, src, domain, CollectOptions{})
}

// EnumerateWith is Enumerate with the inference bounds made explicit.
func EnumerateWith(ctx context.Context, src Source, domain string, opts CollectOptions) (Result, error) {
	domain = normaliseName(domain)

	if entry, err := readCache(src.Name(), domain, CacheTTL); err == nil {
		result := CollectWith(domain, entry.Certificates, opts)
		result.Source = src.Name() + " (cached " + entry.Fetched.Format(time.RFC3339) + ")"
		return result, nil
	}

	certs, err := src.Search(ctx, domain)
	if err != nil {
		if entry, cacheErr := readCache(src.Name(), domain, 0); cacheErr == nil {
			result := CollectWith(domain, entry.Certificates, opts)
			result.Source = src.Name() + " (stale cache from " +
				entry.Fetched.Format(time.RFC3339) + "; the source was unreachable)"
			return result, nil
		}
		return Result{}, err
	}

	// A cache that cannot be written costs only a repeated query, so it is not
	// worth failing the check over.
	_ = writeCache(src.Name(), domain, cacheEntry{
		Source: src.Name(), Fetched: time.Now().UTC(), Certificates: certs,
	})

	result := CollectWith(domain, certs, opts)
	result.Source = src.Name()
	return result, nil
}

func readCache(source, domain string, ttl time.Duration) (cacheEntry, error) {
	var entry cacheEntry

	path, err := cachePath(source, domain)
	if err != nil {
		return entry, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return entry, err
	}
	if ttl > 0 && time.Since(info.ModTime()) > ttl {
		return entry, fmt.Errorf("cache entry is stale")
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is built from a sanitised domain
	if err != nil {
		return entry, err
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return entry, err
	}
	if entry.Source != source {
		return cacheEntry{}, fmt.Errorf("cache entry was written by a different source")
	}
	return entry, nil
}

func writeCache(source, domain string, entry cacheEntry) error {
	path, err := cachePath(source, domain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Written and renamed, so a run interrupted mid-write cannot leave a
	// truncated file that parses as a shorter list of names.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cachePath names the file after the source and domain.
//
// The domain is sanitised rather than used directly: a name containing a path
// separator, or consisting of dots, would otherwise let a caller write outside
// the cache directory.
func cachePath(source, domain string) (string, error) {
	dir, err := CacheDir()
	if err != nil {
		return "", err
	}
	name := sanitise(source) + "-" + sanitise(domain)
	if name == "-" {
		return "", fmt.Errorf("error: cannot cache results for an empty domain")
	}
	return filepath.Join(dir, name+".json"), nil
}

// sanitise reduces a string to characters that are safe in a filename.
func sanitise(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	// A name made only of dots would resolve to a directory rather than a file.
	if strings.Trim(b.String(), ".") == "" {
		return "_"
	}
	return b.String()
}

// CachePathFor exposes the cache location for a domain, so the CLI can tell a
// user where results were stored and what to delete to force a refresh.
func CachePathFor(source Source, domain string) (string, error) {
	return cachePath(source.Name(), normaliseName(domain))
}
