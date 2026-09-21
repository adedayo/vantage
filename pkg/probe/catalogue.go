package probe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/adedayo/vantage/pkg/observation"
)

// ServiceDefinition describes a well-known service declaration. It is
// metadata only: using a definition never schedules or performs a probe.
type ServiceDefinition struct {
	Name string
	// Rank is the curated probe priority; lower values are considered first.
	// It is not a claim about a universal Internet-wide frequency ranking.
	Rank        int
	Port        uint16
	Transport   string
	Protocol    string
	Layer       observation.ServiceLayer
	Description string
}

// DiscoveryProfile groups candidate-service breadth by operator intent rather
// than exposing only a raw port count.
type DiscoveryProfile string

const (
	// DiscoveryMostCommon is the fast recurring sweep.
	DiscoveryMostCommon DiscoveryProfile = "most-common"
	// DiscoveryExtended adds lower-frequency but high-impact infrastructure and
	// alternate service ports.
	DiscoveryExtended DiscoveryProfile = "extended"
	// DiscoveryCustom means the caller supplies the service declarations.
	DiscoveryCustom DiscoveryProfile = "custom"
)

const mostCommonLimit = 10

// Request builds an explicit request for this service at host. The caller
// still decides whether the target is in scope before passing it to a Prober.
func (s ServiceDefinition) Request(host string) Request {
	return Request{
		Target: Target{Host: host, Port: s.Port, Protocol: s.Protocol, Service: s.Name},
		Layer:  s.Layer,
	}
}

// CommonServices returns a curated, TCP-oriented set of likely useful service
// declarations. The set is inspired by the high-frequency service coverage
// found in port scanners, but it is not an automatic scan list and does not
// claim to reproduce any scanner's ranking database.
func CommonServices() []ServiceDefinition {
	services := []ServiceDefinition{
		{Name: "ftp", Rank: 8, Port: 21, Transport: transportTCP, Protocol: "ftp", Layer: observation.ServiceLayerTCP, Description: "File Transfer Protocol"},
		{Name: "ssh", Rank: 3, Port: 22, Transport: transportTCP, Protocol: "ssh", Layer: observation.ServiceLayerTCP, Description: "Secure Shell"},
		{Name: "telnet", Rank: 33, Port: 23, Transport: transportTCP, Protocol: "telnet", Layer: observation.ServiceLayerTCP, Description: "Telnet"},
		{Name: "smtp", Rank: 4, Port: 25, Transport: transportTCP, Protocol: protocolSMTP, Layer: observation.ServiceLayerStartTLS, Description: "SMTP with STARTTLS"},
		{Name: "dns-tcp", Rank: 5, Port: 53, Transport: transportTCP, Protocol: "dns", Layer: observation.ServiceLayerTCP, Description: "DNS over TCP"},
		{Name: "http", Rank: 2, Port: 80, Transport: transportTCP, Protocol: protocolHTTP, Layer: observation.ServiceLayerHTTP, Description: "HTTP"},
		{Name: "pop3", Rank: 10, Port: 110, Transport: transportTCP, Protocol: protocolPOP3, Layer: observation.ServiceLayerStartTLS, Description: "POP3 with STLS"},
		{Name: "rpcbind", Rank: 27, Port: 111, Transport: transportTCP, Protocol: "rpcbind", Layer: observation.ServiceLayerTCP, Description: "RPC port mapper"},
		{Name: "imap", Rank: 9, Port: 143, Transport: transportTCP, Protocol: protocolIMAP, Layer: observation.ServiceLayerStartTLS, Description: "IMAP with STARTTLS"},
		{Name: "msrpc", Rank: 32, Port: 135, Transport: transportTCP, Protocol: "msrpc", Layer: observation.ServiceLayerTCP, Description: "Microsoft RPC endpoint mapper"},
		{Name: "netbios-ssn", Rank: 7, Port: 139, Transport: transportTCP, Protocol: "netbios-ssn", Layer: observation.ServiceLayerTCP, Description: "NetBIOS session service"},
		{Name: "https", Rank: 1, Port: 443, Transport: transportTCP, Protocol: protocolHTTPS, Layer: observation.ServiceLayerHTTP, Description: "HTTPS"},
		{Name: "smb", Rank: 6, Port: 445, Transport: transportTCP, Protocol: "smb", Layer: observation.ServiceLayerTCP, Description: "Server Message Block"},
		{Name: "smtps", Rank: 22, Port: 465, Transport: transportTCP, Protocol: "smtps", Layer: observation.ServiceLayerTLS, Description: "SMTP over implicit TLS"},
		{Name: "ipp", Rank: 31, Port: 631, Transport: transportTCP, Protocol: "ipp", Layer: observation.ServiceLayerTCP, Description: "Internet Printing Protocol"},
		{Name: "submission", Rank: 11, Port: 587, Transport: transportTCP, Protocol: "submission", Layer: observation.ServiceLayerStartTLS, Description: "Message submission with STARTTLS"},
		{Name: "imaps", Rank: 20, Port: 993, Transport: transportTCP, Protocol: "imaps", Layer: observation.ServiceLayerTLS, Description: "IMAP over implicit TLS"},
		{Name: "pop3s", Rank: 21, Port: 995, Transport: transportTCP, Protocol: "pop3s", Layer: observation.ServiceLayerTLS, Description: "POP3 over implicit TLS"},
		{Name: "mssql", Rank: 17, Port: 1433, Transport: transportTCP, Protocol: "mssql", Layer: observation.ServiceLayerTCP, Description: "Microsoft SQL Server"},
		{Name: "oracle", Rank: 29, Port: 1521, Transport: transportTCP, Protocol: "oracle", Layer: observation.ServiceLayerTCP, Description: "Oracle listener"},
		{Name: "nfs", Rank: 28, Port: 2049, Transport: transportTCP, Protocol: "nfs", Layer: observation.ServiceLayerTCP, Description: "Network File System"},
		{Name: "docker", Rank: 26, Port: 2375, Transport: transportTCP, Protocol: "docker", Layer: observation.ServiceLayerTCP, Description: "Docker Engine API"},
		{Name: "docker-tls", Rank: 25, Port: 2376, Transport: transportTCP, Protocol: "docker", Layer: observation.ServiceLayerTLS, Description: "Docker Engine API over TLS"},
		{Name: "mysql", Rank: 15, Port: 3306, Transport: transportTCP, Protocol: "mysql", Layer: observation.ServiceLayerTCP, Description: "MySQL"},
		{Name: "rdp", Rank: 12, Port: 3389, Transport: transportTCP, Protocol: "rdp", Layer: observation.ServiceLayerTCP, Description: "Remote Desktop Protocol"},
		{Name: "postgresql", Rank: 16, Port: 5432, Transport: transportTCP, Protocol: "postgresql", Layer: observation.ServiceLayerTCP, Description: "PostgreSQL"},
		{Name: "vnc", Rank: 30, Port: 5900, Transport: transportTCP, Protocol: "vnc", Layer: observation.ServiceLayerTCP, Description: "Virtual Network Computing"},
		{Name: "redis", Rank: 18, Port: 6379, Transport: transportTCP, Protocol: "redis", Layer: observation.ServiceLayerTCP, Description: "Redis"},
		{Name: "kubernetes-api", Rank: 23, Port: 6443, Transport: transportTCP, Protocol: protocolHTTPS, Layer: observation.ServiceLayerHTTP, Description: "Kubernetes API over HTTPS"},
		{Name: "http-alt", Rank: 13, Port: 8080, Transport: transportTCP, Protocol: protocolHTTP, Layer: observation.ServiceLayerHTTP, Description: "Alternative HTTP"},
		{Name: "https-alt", Rank: 14, Port: 8443, Transport: transportTCP, Protocol: protocolHTTPS, Layer: observation.ServiceLayerHTTP, Description: "Alternative HTTPS"},
		{Name: "elasticsearch", Rank: 24, Port: 9200, Transport: transportTCP, Protocol: protocolHTTP, Layer: observation.ServiceLayerHTTP, Description: "Elasticsearch HTTP API"},
		{Name: "mongodb", Rank: 19, Port: 27017, Transport: "tcp", Protocol: "mongodb", Layer: observation.ServiceLayerTCP, Description: "MongoDB"},
	}
	sort.Slice(services, func(i, j int) bool {
		if services[i].Rank != services[j].Rank {
			return services[i].Rank < services[j].Rank
		}
		return services[i].Port < services[j].Port
	})
	return services
}

// RankedServices returns at most limit common services in curated priority
// order. A non-positive limit returns no services, so callers must opt into a
// bounded breadth explicitly.
func RankedServices(limit int) []ServiceDefinition {
	if limit <= 0 {
		return nil
	}
	services := CommonServices()
	if limit > len(services) {
		limit = len(services)
	}
	return services[:limit]
}

// RankedRequests builds a bounded discovery request set for one already
// discovered host. It does not resolve, dial, or otherwise contact the host.
func RankedRequests(host string, limit int) []Request {
	if strings.TrimSpace(host) == "" || limit <= 0 {
		return nil
	}
	services := RankedServices(limit)
	requests := make([]Request, 0, len(services))
	for _, service := range services {
		requests = append(requests, service.Request(host))
	}
	return requests
}

// RequestsForProfile builds a bounded candidate request set for one already
// discovered host. Custom profiles intentionally return an error: they must
// name their own declarations rather than silently widening the scan.
func RequestsForProfile(host string, profile DiscoveryProfile) ([]Request, error) {
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("discovery host is required")
	}
	switch profile {
	case DiscoveryMostCommon:
		return RankedRequests(host, mostCommonLimit), nil
	case DiscoveryExtended:
		return RankedRequests(host, len(CommonServices())), nil
	case DiscoveryCustom:
		return nil, fmt.Errorf("custom discovery profile requires explicit services")
	default:
		return nil, fmt.Errorf("unknown discovery profile %q", profile)
	}
}

// FindCommonService returns a named declaration from the curated catalogue.
func FindCommonService(name string) (ServiceDefinition, bool) {
	for _, service := range CommonServices() {
		if service.Name == name {
			return service, true
		}
	}
	return ServiceDefinition{}, false
}

// CustomService creates a declaration for an operator-specific or
// non-standard port. It performs metadata validation but never contacts the
// target.
func CustomService(name string, port uint16, transport, protocol string, layer observation.ServiceLayer, description string) (ServiceDefinition, error) {
	definition := ServiceDefinition{
		Name: name, Port: port, Transport: transport,
		Protocol: protocol, Layer: layer, Description: description,
	}
	if err := definition.Validate(); err != nil {
		return ServiceDefinition{}, err
	}
	return definition, nil
}

// Validate checks a service declaration before it is turned into a request.
func (s ServiceDefinition) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("service name is required")
	}
	if s.Port == 0 {
		return fmt.Errorf("service %q has invalid port 0", s.Name)
	}
	if strings.TrimSpace(s.Transport) == "" || strings.TrimSpace(s.Protocol) == "" {
		return fmt.Errorf("service %q requires transport and protocol", s.Name)
	}
	switch s.Layer {
	case observation.ServiceLayerTCP, observation.ServiceLayerTLS,
		observation.ServiceLayerHTTP, observation.ServiceLayerStartTLS:
		return nil
	default:
		return fmt.Errorf("service %q has unsupported probe layer %q", s.Name, s.Layer)
	}
}
