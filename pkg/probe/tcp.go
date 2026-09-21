// Package probe performs bounded, declared-service protocol probes.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/adedayo/vantage/pkg/observation"
)

const (
	transportTCP            = "tcp"
	protocolHTTP            = "http"
	protocolHTTPS           = "https"
	protocolSMTP            = "smtp"
	protocolIMAP            = "imap"
	protocolPOP3            = "pop3"
	errInvalidServiceTarget = "invalid service target"
	responseTCPRefused      = "tcp_refused"

	// DefaultProfile is the initial bounded profile for explicitly declared
	// service endpoints.
	DefaultProfile = "declared-services"
	// DefaultTimeout prevents a probe from holding a worker indefinitely.
	DefaultTimeout = 5 * time.Second
)

// Dialer is the network boundary for a probe. Consumers can wrap it with
// scope and egress policy; tests can provide a hermetic implementation.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Target identifies one operator-declared service endpoint.
type Target struct {
	Host     string
	Port     uint16
	Protocol string
	Service  string
}

// Options configures one probe without introducing package-global network
// policy.
type Options struct {
	Dialer  Dialer
	Timeout time.Duration
	Profile string
	Now     func() time.Time
}

// TCP probes one declared TCP endpoint. It never promotes a TCP response to
// TLS, HTTP or STARTTLS evidence.
func TCP(ctx context.Context, target Target, opts Options) observation.ServiceObservation {
	observedAt := time.Now
	if opts.Now != nil {
		observedAt = opts.Now
	}
	profile := opts.Profile
	if profile == "" {
		profile = DefaultProfile
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	result := observation.ServiceObservation{
		Host: target.Host, Port: target.Port, Transport: transportTCP,
		Protocol: target.Protocol, Service: target.Service, Layer: observation.ServiceLayerTCP,
		State: observation.ServiceUnknown, ObservedAt: observedAt(),
		ProbeProfile: profile,
	}
	if result.Protocol == "" {
		result.Protocol = transportTCP
	}
	if target.Host == "" || target.Port == 0 {
		result.Evidence.Error = errInvalidServiceTarget
		return result
	}
	if opts.Dialer == nil {
		opts.Dialer = &net.Dialer{}
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := opts.Dialer.DialContext(probeCtx, transportTCP, net.JoinHostPort(target.Host, fmt.Sprint(target.Port)))
	if err == nil {
		_ = conn.Close()
		result.State = observation.ServiceResponding
		result.Evidence.ResponseClass = "tcp_connected"
		return result
	}
	result.Evidence.Error = boundedError(err)
	if connectionRefused(err) {
		result.State = observation.ServiceNotResponding
		result.Evidence.ResponseClass = responseTCPRefused
	}
	return result
}

func connectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

func boundedError(err error) string {
	const maxErrorLength = 256
	message := err.Error()
	if len(message) > maxErrorLength {
		return message[:maxErrorLength]
	}
	return message
}
