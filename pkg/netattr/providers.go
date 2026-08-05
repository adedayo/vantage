package netattr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Provider is a cloud or CDN operator whose announced ranges are known.
type Provider struct {
	// Name is the operator.
	Name string
	// Source is the URL the ranges were published at, retained so a finding
	// can cite where the attribution came from.
	Source string
	// Ranges are the announced prefixes.
	Ranges []ProviderRange
}

// ProviderRange is one announced prefix and what is known about where it is.
type ProviderRange struct {
	Prefix netip.Prefix
	// Region is the operator's own region identifier, e.g. "eu-west-1". It is
	// empty when the operator does not publish one.
	Region string
}

// Attribution is what could be established about an address.
type Attribution struct {
	// Address is the address looked up.
	Address netip.Addr
	// Special is the special-purpose registry entry, when the address is in
	// one.
	Special *SpecialRange
	// Provider is the operator announcing the address, when known.
	Provider string
	// Source cites where the provider's ranges came from.
	Source string
	// Region is the operator's region identifier, when published.
	Region string
	// Jurisdiction is the ISO 3166-1 alpha-2 country the region sits in, when
	// the mapping is known. Empty means unknown, never "assume home".
	Jurisdiction string
	// Prefix is the announced prefix that matched.
	Prefix netip.Prefix
}

// Attributed reports whether anything at all was established about the address.
// An unattributed address is not evidence that the host is self-hosted; it is
// evidence that this tool does not know, and the rules must treat it that way.
func (a Attribution) Attributed() bool {
	return a.Special != nil || a.Provider != ""
}

// endpoint is one place a publication can be fetched from, with the parser for
// the shape served there.
type endpoint struct {
	url   string
	parse func([]byte) ([]ProviderRange, error)
}

// providerSource is an operator's ranges and every endpoint they can be
// obtained from, in preference order.
type providerSource struct {
	name string
	// endpoints are tried in order until one yields ranges. A published URL
	// can be withdrawn or moved — crt.sh returned 502 for a full day during
	// development, and Azure's range file lives at a URL that rotates weekly —
	// and a check that fails whenever one endpoint moves is a check people
	// turn off.
	//
	// Only genuinely equivalent endpoints belong here. A near-equivalent that
	// omits regions or covers a different population would produce attributions
	// that look identical to correct ones while being wrong, which is worse
	// than reporting the source as unavailable.
	endpoints []endpoint
}

// providerSources are the published range files this package understands.
//
// Every entry is the operator's own machine-readable publication. Nothing here
// is transcribed by hand: a prefix list maintained in this repository would be
// stale within days and would attribute addresses to the wrong operator with
// the same confidence as a correct answer.
//
// Only Cloudflare publishes a second equivalent endpoint. Google's goog.json
// is deliberately not a fallback for cloud.json: it lists every Google netblock
// including 8.8.8.0/24, carries no region, and would attribute Google's own
// infrastructure to a customer cloud. AWS and Fastly publish one endpoint each.
// For those three the stale cache is the resilience, and its use is disclosed.
//
// Microsoft Azure is absent. Its ranges are published only at a URL carrying a
// rotating GUID and date, of which just the two most recent weekly files are
// retained, so consuming it would fail silently. Coverage is therefore
// incomplete, and the consequence is stated plainly in the rules: an address
// this package cannot attribute yields no finding at all rather than a claim
// that it belongs to nobody.
var providerSources = []providerSource{
	{"Amazon Web Services", []endpoint{
		{"https://ip-ranges.amazonaws.com/ip-ranges.json", parseAWS},
	}},
	{"Google Cloud", []endpoint{
		{"https://www.gstatic.com/ipranges/cloud.json", parseGCP},
	}},
	{"Cloudflare", []endpoint{
		{"https://www.cloudflare.com/ips-v4", parsePlainList},
		{"https://api.cloudflare.com/client/v4/ips", parseCloudflareAPIv4},
	}},
	{"Cloudflare", []endpoint{
		{"https://www.cloudflare.com/ips-v6", parsePlainList},
		{"https://api.cloudflare.com/client/v4/ips", parseCloudflareAPIv6},
	}},
	{"Fastly", []endpoint{
		{"https://api.fastly.com/public-ip-list", parseFastly},
	}},
}

// load returns the first endpoint's ranges that could be fetched and parsed,
// the URL used, when the data was obtained, and the reason each earlier
// endpoint was skipped.
//
// A nil range slice means every endpoint failed. That is distinct from an empty
// one, which would be a publication that genuinely lists nothing.
func (s providerSource) load(ctx context.Context, l *Loader) ([]ProviderRange, string, time.Time, []string) {
	var failures []string
	for _, e := range s.endpoints {
		data, at, err := fetchCached(ctx, l, e.url)
		if err != nil {
			failures = append(failures, e.url+": "+err.Error())
			continue
		}
		ranges, err := e.parse(data)
		if err != nil {
			// A parse failure is as disqualifying as an unreachable endpoint:
			// the operator changed a format this package no longer understands,
			// and guessing at the new one would attribute addresses wrongly.
			failures = append(failures, e.url+": "+err.Error())
			continue
		}
		return ranges, e.url, at, failures
	}
	return nil, "", time.Time{}, failures
}

// SourceProvenance records where one operator's ranges came from and when.
//
// Attribution is derived from data this tool fetches, so an attribution can
// change without the audited domain changing at all. Spec 013 diffs records
// between runs and requires that false drift be avoidable, so a consumer needs
// to be able to tell "the host moved" from "our data changed". That is only
// possible if the data's origin and age travel with the result.
type SourceProvenance struct {
	// Provider is the operator the ranges describe.
	Provider string
	// URL is the endpoint the data was obtained from, which may be a fallback
	// rather than the preferred one.
	URL string
	// Fetched is when the data was obtained, not when it was used.
	Fetched time.Time
}

// Set is a loaded collection of provider ranges.
type Set struct {
	// Providers are the operators whose ranges loaded successfully.
	Providers []Provider
	// Failed names the sources that could not be loaded, so a caller can say
	// "coverage was incomplete" rather than "not in a cloud".
	Failed []string
	// Stale names the sources served from a cache entry older than CacheTTL,
	// with the age, because the operator's endpoint could not be reached.
	// Serving week-old data is defensible; doing so without saying is not.
	Stale []string
	// Provenance records where each operator's ranges came from and when, so a
	// consumer diffing two runs can tell a moved host from refreshed data.
	Provenance []SourceProvenance
	// Fetched is when the data was obtained, which is what lets a reader judge
	// how stale an attribution may be.
	Fetched time.Time
}

// Lookup attributes an address.
//
// Special-purpose space is checked first and short-circuits: an RFC 1918
// address cannot also be an operator's announced range, and a provider file
// that claimed otherwise would be wrong.
func (s Set) Lookup(addr netip.Addr) Attribution {
	addr = addr.Unmap()
	a := Attribution{Address: addr}

	if sr, ok := LookupSpecial(addr); ok {
		a.Special = &sr
		return a
	}

	// The most specific announcement wins. Operators publish overlapping
	// prefixes — a regional range inside a global aggregate — and taking the
	// first match would report the aggregate's region for an address the
	// operator places elsewhere.
	best := -1
	for _, p := range s.Providers {
		for _, r := range p.Ranges {
			if !r.Prefix.Contains(addr) || r.Prefix.Bits() <= best {
				continue
			}
			best = r.Prefix.Bits()
			a.Provider, a.Source, a.Region, a.Prefix = p.Name, p.Source, r.Region, r.Prefix
			a.Jurisdiction = JurisdictionOf(r.Region)
		}
	}
	return a
}

// Complete reports whether every source loaded. When false, an address with no
// provider match may simply belong to an operator whose ranges are missing.
func (s Set) Complete() bool { return len(s.Failed) == 0 }

// parseAWS reads the AWS ip-ranges.json publication.
func parseAWS(data []byte) ([]ProviderRange, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Region     string `json:"region"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	ranges := make([]ProviderRange, 0, len(doc.Prefixes)+len(doc.IPv6Prefixes))
	for _, p := range doc.Prefixes {
		if pfx, err := netip.ParsePrefix(p.IPPrefix); err == nil {
			ranges = append(ranges, ProviderRange{Prefix: pfx, Region: p.Region})
		}
	}
	for _, p := range doc.IPv6Prefixes {
		if pfx, err := netip.ParsePrefix(p.IPv6Prefix); err == nil {
			ranges = append(ranges, ProviderRange{Prefix: pfx, Region: p.Region})
		}
	}
	return requireRanges(ranges)
}

// parseGCP reads the Google Cloud cloud.json publication.
func parseGCP(data []byte) ([]ProviderRange, error) {
	var doc struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
			Scope      string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	ranges := make([]ProviderRange, 0, len(doc.Prefixes))
	for _, p := range doc.Prefixes {
		raw := p.IPv4Prefix
		if raw == "" {
			raw = p.IPv6Prefix
		}
		if pfx, err := netip.ParsePrefix(raw); err == nil {
			ranges = append(ranges, ProviderRange{Prefix: pfx, Region: p.Scope})
		}
	}
	return requireRanges(ranges)
}

// parseFastly reads the Fastly public IP list.
func parseFastly(data []byte) ([]ProviderRange, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	ranges := make([]ProviderRange, 0, len(doc.Addresses)+len(doc.IPv6Addresses))
	for _, raw := range append(doc.Addresses, doc.IPv6Addresses...) {
		if pfx, err := netip.ParsePrefix(raw); err == nil {
			ranges = append(ranges, ProviderRange{Prefix: pfx})
		}
	}
	return requireRanges(ranges)
}

// parsePlainList reads a newline-separated prefix list.
func parsePlainList(data []byte) ([]ProviderRange, error) {
	var ranges []ProviderRange
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if pfx, err := netip.ParsePrefix(line); err == nil {
			ranges = append(ranges, ProviderRange{Prefix: pfx})
		}
	}
	return requireRanges(ranges)
}

// parseCloudflareAPIv4 and parseCloudflareAPIv6 read Cloudflare's JSON API,
// which serves both families in one document and is the fallback for the two
// plain-text lists.
//
// The families are extracted separately so each plain-text list falls back to
// the equivalent half. Returning both from either would double-count the
// ranges when only one endpoint had failed.
func parseCloudflareAPIv4(data []byte) ([]ProviderRange, error) {
	return parseCloudflareAPI(data, false)
}

func parseCloudflareAPIv6(data []byte) ([]ProviderRange, error) {
	return parseCloudflareAPI(data, true)
}

func parseCloudflareAPI(data []byte, wantV6 bool) ([]ProviderRange, error) {
	var doc struct {
		Success bool `json:"success"`
		Result  struct {
			IPv4CIDRs []string `json:"ipv4_cidrs"`
			IPv6CIDRs []string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if !doc.Success {
		// The API reports failure in the body with HTTP 200, so the status code
		// alone would let an error document be parsed as an empty range set.
		return nil, fmt.Errorf("the Cloudflare API reported failure")
	}

	raw := doc.Result.IPv4CIDRs
	if wantV6 {
		raw = doc.Result.IPv6CIDRs
	}

	ranges := make([]ProviderRange, 0, len(raw))
	for _, s := range raw {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			ranges = append(ranges, ProviderRange{Prefix: pfx})
		}
	}
	return requireRanges(ranges)
}

// requireRanges rejects a publication that parsed to nothing.
//
// An operator changing its file format would otherwise leave this package
// silently attributing none of its addresses, which reads identically to that
// operator hosting nothing — a false negative with no symptom.
func requireRanges(ranges []ProviderRange) ([]ProviderRange, error) {
	if len(ranges) == 0 {
		return nil, fmt.Errorf("the published range file contained no usable prefixes")
	}
	return ranges, nil
}
