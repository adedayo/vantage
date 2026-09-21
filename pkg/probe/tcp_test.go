package probe_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/adedayo/vantage/pkg/observation"
	"github.com/adedayo/vantage/pkg/probe"
)

func TestTCPReportsRespondingEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", listener.Addr())
	}
	result := probe.TCP(context.Background(), probe.Target{
		Host: "127.0.0.1", Port: uint16(address.Port),
	}, probe.Options{Now: fixedTime})

	if result.State != observation.ServiceResponding {
		t.Fatalf("state = %q, want responding: %+v", result.State, result)
	}
	if result.Evidence.ResponseClass != "tcp_connected" || !result.ObservedAt.Equal(fixedTime()) {
		t.Fatalf("unexpected evidence: %+v", result)
	}
}

func TestTCPReportsRefusedEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", listener.Addr())
	}
	listener.Close()

	result := probe.TCP(context.Background(), probe.Target{
		Host: "127.0.0.1", Port: uint16(address.Port),
	}, probe.Options{Timeout: time.Second})

	if result.State != observation.ServiceNotResponding {
		t.Fatalf("state = %q, want not_responding: %+v", result.State, result)
	}
}

func TestTCPKeepsCancellationUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := probe.TCP(ctx, probe.Target{Host: "198.51.100.1", Port: 443}, probe.Options{})
	if result.State != observation.ServiceUnknown {
		t.Fatalf("state = %q, want unknown: %+v", result.State, result)
	}
}

func fixedTime() time.Time {
	return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
}
