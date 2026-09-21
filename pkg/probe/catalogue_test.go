package probe_test

import (
	"testing"

	"github.com/adedayo/vantage/pkg/observation"
	"github.com/adedayo/vantage/pkg/probe"
)

func TestCommonServicesAreValidAndUnique(t *testing.T) {
	services := probe.CommonServices()
	seen := make(map[string]struct{}, len(services))
	for _, service := range services {
		if err := service.Validate(); err != nil {
			t.Fatalf("%s: %v", service.Name, err)
		}
		key := service.Name + ":" + service.Protocol
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate service declaration %q", key)
		}
		seen[key] = struct{}{}
	}
	if len(services) < 20 {
		t.Fatalf("common service catalogue has %d entries, want at least 20", len(services))
	}
	for i := 1; i < len(services); i++ {
		if services[i-1].Rank >= services[i].Rank {
			t.Fatalf("services are not ranked: %d before %d", services[i-1].Rank, services[i].Rank)
		}
	}
}

func TestRankedServicesRequiresAnExplicitBound(t *testing.T) {
	if services := probe.RankedServices(0); len(services) != 0 {
		t.Fatalf("zero limit returned %d services", len(services))
	}
	services := probe.RankedServices(5)
	if len(services) != 5 || services[0].Name != "https" || services[1].Name != "http" {
		t.Fatalf("top services = %+v", services)
	}
}

func TestCustomServiceSupportsNonStandardPort(t *testing.T) {
	service, err := probe.CustomService(
		"internal-dashboard", 9443, "tcp", "https",
		observation.ServiceLayerHTTP, "Operator-specific HTTPS service",
	)
	if err != nil {
		t.Fatalf("custom service: %v", err)
	}
	request := service.Request("dashboard.example.test")
	if request.Target.Port != 9443 || request.Target.Protocol != "https" || request.Target.Service != "internal-dashboard" || request.Layer != observation.ServiceLayerHTTP {
		t.Fatalf("request = %+v", request)
	}
}

func TestRankedRequestsBuildsBoundedDiscoverySet(t *testing.T) {
	requests := probe.RankedRequests("asset.example.test", 3)
	if len(requests) != 3 {
		t.Fatalf("request count = %d, want 3", len(requests))
	}
	if requests[0].Target.Service != "https" || requests[1].Target.Service != "http" || requests[2].Target.Service != "ssh" {
		t.Fatalf("ranked services = %+v", requests)
	}
	if probe.RankedRequests("", 3) != nil || probe.RankedRequests("asset.example.test", 0) != nil {
		t.Fatal("invalid discovery request bounds should return nil")
	}
}

func TestDiscoveryProfilesSeparateFastAndExtendedBreadth(t *testing.T) {
	common, err := probe.RequestsForProfile("asset.example.test", probe.DiscoveryMostCommon)
	if err != nil || len(common) != 10 {
		t.Fatalf("most-common requests = %d, err = %v", len(common), err)
	}
	extended, err := probe.RequestsForProfile("asset.example.test", probe.DiscoveryExtended)
	if err != nil || len(extended) <= len(common) {
		t.Fatalf("extended requests = %d, common = %d, err = %v", len(extended), len(common), err)
	}
	if _, err := probe.RequestsForProfile("asset.example.test", probe.DiscoveryCustom); err == nil {
		t.Fatal("custom profile should require explicit service declarations")
	}
}

func TestFindCommonServiceByName(t *testing.T) {
	service, ok := probe.FindCommonService("https")
	if !ok || service.Port != 443 || service.Layer != observation.ServiceLayerHTTP {
		t.Fatalf("https service = %+v, found = %v", service, ok)
	}
}

func TestCatalogueOnlyBuildsRequests(t *testing.T) {
	service, err := probe.CustomService("private-api", 12345, "tcp", "https", observation.ServiceLayerTLS, "private API")
	if err != nil {
		t.Fatalf("custom service: %v", err)
	}
	request := service.Request("private.example.test")
	if request.Target.Host != "private.example.test" {
		t.Fatalf("request target = %+v", request.Target)
	}
}
