package probe_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adedayo/vantage/pkg/observation"
	"github.com/adedayo/vantage/pkg/probe"
)

type countingDialer struct {
	Calls  atomic.Int32
	Active atomic.Int32
	Peak   atomic.Int32
}

type countingConn struct {
	net.Conn
	dialer *countingDialer
}

func (c *countingConn) Close() error {
	err := c.Conn.Close()
	c.dialer.Active.Add(-1)
	return err
}

func (d *countingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.Calls.Add(1)
	active := d.Active.Add(1)
	for {
		peak := d.Peak.Load()
		if active <= peak || d.Peak.CompareAndSwap(peak, active) {
			break
		}
	}
	left, right := net.Pipe()
	go func() {
		<-time.After(time.Millisecond)
		right.Close()
	}()
	return &countingConn{Conn: left, dialer: d}, nil
}

func TestServiceProberDeniesOutOfScopeBeforeDial(t *testing.T) {
	dialer := &countingDialer{}
	prober := probe.ServiceProber{Profile: probe.Profile{
		Dialer: dialer,
		Allow:  func(probe.Target) error { return errors.New("outside declared scope") },
	}}

	result := prober.Probe(context.Background(), probe.Request{
		Target: probe.Target{Host: "out-of-scope.example", Port: 443},
		Layer:  observation.ServiceLayerTCP,
	})
	if result.State != observation.ServiceUnknown || dialer.Calls.Load() != 0 {
		t.Fatalf("scope denial = %+v, dial calls = %d", result, dialer.Calls.Load())
	}
}

func TestServiceProberBoundsConcurrencyAndBudget(t *testing.T) {
	dialer := &countingDialer{}
	prober := probe.ServiceProber{Profile: probe.Profile{
		Dialer: dialer, MaxConcurrency: 2, MaxProbes: 3,
	}}
	requests := make([]probe.Request, 5)
	for i := range requests {
		requests[i] = probe.Request{
			Target: probe.Target{Host: "127.0.0.1", Port: 1},
			Layer:  observation.ServiceLayerTCP,
		}
	}
	results := prober.ProbeMany(context.Background(), requests)
	if dialer.Calls.Load() != 3 {
		t.Fatalf("dial calls = %d, want 3", dialer.Calls.Load())
	}
	if dialer.Peak.Load() > 2 {
		t.Fatalf("peak concurrency = %d, want at most 2", dialer.Peak.Load())
	}
	for _, result := range results[3:] {
		if result.State != observation.ServiceUnknown || result.Evidence.Error != "probe budget exceeded" {
			t.Fatalf("budget result = %+v", result)
		}
	}
}

func TestServiceProberRequiresAnExplicitLayer(t *testing.T) {
	dialer := &countingDialer{}
	prober := probe.ServiceProber{Profile: probe.Profile{Dialer: dialer}}
	result := prober.Probe(context.Background(), probe.Request{
		Target: probe.Target{Host: "example.test", Port: 443},
	})
	if result.State != observation.ServiceUnknown || dialer.Calls.Load() != 0 {
		t.Fatalf("missing layer = %+v, dial calls = %d", result, dialer.Calls.Load())
	}
}
