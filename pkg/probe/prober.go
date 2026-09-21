package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/adedayo/vantage/pkg/observation"
)

const (
	// DefaultMaxConcurrency bounds simultaneous declared-service probes.
	DefaultMaxConcurrency = 8
	// DefaultMaxProbes bounds one batch when the caller does not provide a
	// request budget.
	DefaultMaxProbes = 100
)

// ScopeGuard is checked before any transport is called. A rejected target
// therefore produces no network request.
type ScopeGuard func(Target) error

// Profile declares the resource and egress policy for a service-probe batch.
type Profile struct {
	Name           string
	Timeout        time.Duration
	MaxConcurrency int
	MaxProbes      int
	Allow          ScopeGuard
	Dialer         Dialer
	HTTPClient     HTTPDoer
	TLSConfig      *tls.Config
	ServerName     string
	Now            func() time.Time
}

// Request identifies one explicitly declared service and the layer to assess.
type Request struct {
	Target Target
	Layer  observation.ServiceLayer
}

// Prober is the embedding contract for service observations.
type Prober interface {
	Probe(context.Context, Request) observation.ServiceObservation
	ProbeMany(context.Context, []Request) []observation.ServiceObservation
}

// ServiceProber executes declared-service requests under one bounded profile.
type ServiceProber struct {
	Profile Profile
}

var _ Prober = (*ServiceProber)(nil)

// Probe executes one request after applying the profile's scope guard.
func (p *ServiceProber) Probe(ctx context.Context, request Request) observation.ServiceObservation {
	profile := p.profile()
	if request.Layer == "" {
		return unavailable(request, profile, "probe layer is required")
	}
	if profile.Allow != nil {
		if err := profile.Allow(request.Target); err != nil {
			return unavailable(request, profile, fmt.Sprintf("scope denied: %s", boundedError(err)))
		}
	}
	return p.run(ctx, request, profile)
}

// ProbeMany executes requests with bounded concurrency and a total request
// budget. Results retain request order, making them deterministic for callers.
func (p *ServiceProber) ProbeMany(ctx context.Context, requests []Request) []observation.ServiceObservation {
	results := make([]observation.ServiceObservation, len(requests))
	if len(requests) == 0 {
		return results
	}
	profile := p.profile()
	budget := profile.MaxProbes
	if budget > len(requests) {
		budget = len(requests)
	}

	for i := budget; i < len(requests); i++ {
		results[i] = unavailable(requests[i], profile, "probe budget exceeded")
	}
	workers := profile.MaxConcurrency
	if workers > budget {
		workers = budget
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					results[index] = unavailable(requests[index], profile, "probe cancelled")
					continue
				}
				results[index] = p.Probe(ctx, requests[index])
			}
		}()
	}
	for index := 0; index < budget; index++ {
		select {
		case jobs <- index:
		case <-ctx.Done():
			for remaining := index; remaining < budget; remaining++ {
				results[remaining] = unavailable(requests[remaining], profile, "probe cancelled")
			}
			close(jobs)
			wg.Wait()
			return results
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func (p *ServiceProber) run(ctx context.Context, request Request, profile Profile) observation.ServiceObservation {
	switch request.Layer {
	case observation.ServiceLayerTCP:
		return TCP(ctx, request.Target, Options{
			Dialer: profile.Dialer, Timeout: profile.Timeout,
			Profile: profile.Name, Now: profile.Now,
		})
	case observation.ServiceLayerTLS:
		return TLS(ctx, request.Target, TLSOptions{
			Dialer: profile.Dialer, Timeout: profile.Timeout,
			Profile: profile.Name, Now: profile.Now,
			TLSConfig: profile.TLSConfig, ServerName: profile.ServerName,
		})
	case observation.ServiceLayerHTTP:
		return HTTP(ctx, request.Target, HTTPOptions{
			Client: profile.HTTPClient, Timeout: profile.Timeout,
			Profile: profile.Name, Now: profile.Now,
		})
	case observation.ServiceLayerStartTLS:
		return StartTLS(ctx, request.Target, StartTLSOptions{
			Dialer: profile.Dialer, Timeout: profile.Timeout,
			Profile: profile.Name, Now: profile.Now,
			TLSConfig: profile.TLSConfig, ServerName: profile.ServerName,
		})
	default:
		return unavailable(request, profile, "unsupported probe layer")
	}
}

func (p *ServiceProber) profile() Profile {
	profile := p.Profile
	if profile.Name == "" {
		profile.Name = DefaultProfile
	}
	if profile.Timeout <= 0 {
		profile.Timeout = DefaultTimeout
	}
	if profile.MaxConcurrency <= 0 {
		profile.MaxConcurrency = DefaultMaxConcurrency
	}
	if profile.MaxProbes <= 0 {
		profile.MaxProbes = DefaultMaxProbes
	}
	return profile
}

func unavailable(request Request, profile Profile, reason string) observation.ServiceObservation {
	now := time.Now
	if profile.Now != nil {
		now = profile.Now
	}
	protocol := request.Target.Protocol
	if protocol == "" {
		protocol = string(request.Layer)
	}
	return observation.ServiceObservation{
		Host: request.Target.Host, Port: request.Target.Port,
		Transport: transportTCP, Protocol: protocol, Service: request.Target.Service, Layer: request.Layer,
		State:      observation.ServiceUnknown,
		Evidence:   observation.ServiceEvidence{Error: reason},
		ObservedAt: now(), ProbeProfile: profile.Name,
	}
}
