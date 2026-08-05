package audit

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// ThirdPartyService names a service that is neither the operator's nor the
// target's, which a check must contact to do its work.
//
// These are named constants rather than free strings so that a consumer can
// consent to a specific service, and so that a check added in a later release
// which contacts something new cannot be mistaken for one already agreed to.
type ThirdPartyService string

// The third-party services vantage contacts. Adding a check that contacts a
// service not listed here is a registry validation failure, which is the point:
// a new external dependency must be a deliberate, reviewed act.
const (
	// ServiceCertSpotter is the Cert Spotter Certificate Transparency API.
	ServiceCertSpotter ThirdPartyService = "certspotter"
	// ServiceCRTSh is crt.sh, the CT log search fallback.
	ServiceCRTSh ThirdPartyService = "crtsh"
	// ServiceAWSRanges is Amazon's published IP range file.
	ServiceAWSRanges ThirdPartyService = "aws-ip-ranges"
	// ServiceGCPRanges is Google Cloud's published IP range file.
	ServiceGCPRanges ThirdPartyService = "gcp-ip-ranges"
	// ServiceCloudflareRanges is Cloudflare's published IP range lists.
	ServiceCloudflareRanges ThirdPartyService = "cloudflare-ip-ranges"
	// ServiceFastlyRanges is Fastly's published IP range list.
	ServiceFastlyRanges ThirdPartyService = "fastly-ip-ranges"
)

// serviceEndpoints maps each service to the hosts it is reached at. This is
// what lets an embedding consumer build an allowlist keyed on service name and
// enforce it at the transport, without having to know the URLs itself.
var serviceEndpoints = map[ThirdPartyService][]string{
	ServiceCertSpotter:      {"api.certspotter.com"},
	ServiceCRTSh:            {"crt.sh"},
	ServiceAWSRanges:        {"ip-ranges.amazonaws.com"},
	ServiceGCPRanges:        {"www.gstatic.com"},
	ServiceCloudflareRanges: {"www.cloudflare.com", "api.cloudflare.com"},
	ServiceFastlyRanges:     {"api.fastly.com"},
}

// Endpoints returns the hostnames a service is reached at.
func (s ThirdPartyService) Endpoints() []string {
	hosts := serviceEndpoints[s]
	return append([]string(nil), hosts...)
}

// Known reports whether the service is one vantage declares.
func (s ThirdPartyService) Known() bool {
	_, ok := serviceEndpoints[s]
	return ok
}

// ThirdPartyServices returns every declared service, sorted.
func ThirdPartyServices() []ThirdPartyService {
	services := make([]ThirdPartyService, 0, len(serviceEndpoints))
	for s := range serviceEndpoints {
		services = append(services, s)
	}
	sort.Slice(services, func(i, j int) bool { return services[i] < services[j] })
	return services
}

// ThirdPartyEndpointHosts returns every host any declared service is reached
// at, sorted and deduplicated. An embedding consumer uses this to build a
// default-deny allowlist.
func ThirdPartyEndpointHosts() []string {
	seen := map[string]struct{}{}
	for _, hosts := range serviceEndpoints {
		for _, h := range hosts {
			seen[h] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// ServiceForURL returns the service a URL belongs to, if any. It is the
// inverse of Endpoints, and exists so that a transport enforcing an allowlist
// can report which consented service a permitted request was made under.
func ServiceForURL(rawURL string) (ThirdPartyService, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	for service, hosts := range serviceEndpoints {
		for _, h := range hosts {
			if strings.EqualFold(h, host) {
				return service, true
			}
		}
	}
	return "", false
}

// EgressProfile is a check's structured declaration of what it touches.
//
// Prose documentation of blast radius cannot be enforced, and drifts from the
// code the moment a check changes. Declaring it as data means the help text,
// the operator-facing documentation, a deployment's policy gate and a
// scope-guarding transport are all derived from one statement, and so cannot
// disagree with each other or with what the check actually does.
//
// The zero value declares no egress at all, which is the safe default: a check
// that forgets to declare its egress fails registry validation rather than
// quietly inheriting permission to reach the network.
type EgressProfile struct {
	// Resolver is set when the check issues queries through an ordinary
	// recursive resolver.
	Resolver bool

	// TargetNameservers is set when the check queries the target's own
	// authoritative nameservers directly, bypassing the recursive resolver.
	// This is visible to the target in a way an ordinary query is not, and
	// deployments may reasonably decline it.
	TargetNameservers bool

	// TargetHTTPS is set when the check makes HTTPS requests to the target's
	// own infrastructure — MTA-STS policy retrieval, takeover assessment.
	TargetHTTPS bool

	// ThirdParty names the services the check contacts, if any.
	ThirdParty []ThirdPartyService

	// Intrusive marks a check that goes beyond an ordinary query: a zone
	// transfer request, and anything similar added later. It is never about
	// whether the check is destructive — nothing in vantage is — but about
	// whether a reasonable operator would want to consent before it runs.
	Intrusive bool

	// Offline declares that the check needs no network at all. It exists so
	// that "this check touches nothing" is an explicit statement rather than
	// the accidental meaning of a zero value, which is what allows an
	// undeclared profile to be rejected outright.
	Offline bool
}

// Networks derives the coarse Network classification from the profile.
//
// This is the derivation that keeps the two representations from drifting:
// Network is no longer declared independently, so it cannot contradict the
// profile it summarises.
func (e EgressProfile) Networks() []Network {
	var networks []Network
	if e.Resolver || e.TargetNameservers {
		networks = append(networks, NetworkDNS)
	}
	if e.TargetHTTPS {
		networks = append(networks, NetworkHTTPS)
	}
	if len(e.ThirdParty) > 0 {
		networks = append(networks, NetworkThirdParty)
	}
	if len(networks) == 0 {
		networks = append(networks, NetworkNone)
	}
	return networks
}

// RequiresNetwork reports whether the profile needs egress beyond DNS.
func (e EgressProfile) RequiresNetwork() bool {
	return e.TargetHTTPS || len(e.ThirdParty) > 0
}

// Declared reports whether the profile says anything at all. An undeclared
// profile is a registration error, not a claim of no egress — a check that
// genuinely needs nothing must say so explicitly by being marked offline.
func (e EgressProfile) Declared() bool {
	return e.Resolver || e.TargetNameservers || e.TargetHTTPS ||
		len(e.ThirdParty) > 0 || e.Offline
}

// Describe renders the profile as a short human-readable blast-radius summary,
// for help text and generated documentation.
func (e EgressProfile) Describe() string {
	var parts []string
	if e.Resolver {
		parts = append(parts, "recursive DNS")
	}
	if e.TargetNameservers {
		parts = append(parts, "target nameservers directly")
	}
	if e.TargetHTTPS {
		parts = append(parts, "HTTPS to the target")
	}
	for _, s := range e.ThirdParty {
		parts = append(parts, "third party: "+string(s))
	}
	if len(parts) == 0 {
		return "no network"
	}
	summary := strings.Join(parts, ", ")
	if e.Intrusive {
		summary += " (intrusive)"
	}
	return summary
}

// validate reports whether the profile is coherent.
func (e EgressProfile) validate(check string) error {
	if !e.Declared() {
		return fmt.Errorf("error: check %q does not declare its egress profile", check)
	}
	if e.Offline && (e.Resolver || e.TargetNameservers || e.TargetHTTPS || len(e.ThirdParty) > 0) {
		return fmt.Errorf("error: check %q declares itself offline but also declares egress", check)
	}
	for _, s := range e.ThirdParty {
		if !s.Known() {
			return fmt.Errorf("error: check %q declares unknown third-party service %q", check, s)
		}
	}
	return nil
}
