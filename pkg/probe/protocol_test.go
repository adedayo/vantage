package probe_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/adedayo/vantage/pkg/observation"
	"github.com/adedayo/vantage/pkg/probe"
)

func TestTLSReportsNegotiatedEvidence(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	host, port := splitAddress(t, server.Listener.Addr().String())
	result := probe.TLS(context.Background(), probe.Target{Host: host, Port: port}, probe.TLSOptions{
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, // test server certificate is self-signed
		ServerName: "service.example.test",
	})

	if result.State != observation.ServiceResponding {
		t.Fatalf("state = %q, want responding: %+v", result.State, result)
	}
	if result.Evidence.TLSVersion == "" || result.Evidence.CipherSuite == "" ||
		result.Evidence.CertificateSubject == "" || result.Evidence.SNI != "service.example.test" {
		t.Fatalf("missing TLS evidence: %+v", result.Evidence)
	}
}

func TestHTTPReportsMetadataWithoutBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Server", "bounded-test-server")
		writer.WriteHeader(http.StatusNoContent)
		_, _ = writer.Write([]byte(strings.Repeat("not evidence", 10000)))
	}))
	defer server.Close()

	host, port := splitAddress(t, strings.TrimPrefix(server.URL, "http://"))
	result := probe.HTTP(context.Background(), probe.Target{Host: host, Port: port}, probe.HTTPOptions{})

	if result.State != observation.ServiceResponding || result.Evidence.HTTPStatus != http.StatusNoContent {
		t.Fatalf("unexpected HTTP result: %+v", result)
	}
	if result.Evidence.Server != "bounded-test-server" {
		t.Fatalf("server = %q, want bounded-test-server", result.Evidence.Server)
	}
}

func TestTLSHandshakeFailureRemainsUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	host, port := splitAddress(t, strings.TrimPrefix(server.URL, "http://"))
	result := probe.TLS(context.Background(), probe.Target{Host: host, Port: port}, probe.TLSOptions{})
	if result.State != observation.ServiceUnknown {
		t.Fatalf("state = %q, want unknown after TCP response without TLS: %+v", result.State, result)
	}
}

func splitAddress(t *testing.T, address string) (string, uint16) {
	t.Helper()
	parts := strings.Split(address, ":")
	if len(parts) != 2 {
		t.Fatalf("unexpected test address %q", address)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("parse test port: %v", err)
	}
	return parts[0], uint16(port)
}
