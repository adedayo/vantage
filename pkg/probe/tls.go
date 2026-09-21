package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/adedayo/vantage/pkg/observation"
)

// TLSOptions configures a single TLS handshake. Config is cloned before the
// probe changes its server name, so a caller's policy is never mutated.
type TLSOptions struct {
	Dialer     Dialer
	Timeout    time.Duration
	Profile    string
	Now        func() time.Time
	TLSConfig  *tls.Config
	ServerName string
}

// TLS performs one bounded TLS handshake and records only certificate summary
// data, never certificate bytes or application payload.
func TLS(ctx context.Context, target Target, opts TLSOptions) observation.ServiceObservation {
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
		Protocol: target.Protocol, Service: target.Service, Layer: observation.ServiceLayerTLS,
		State: observation.ServiceUnknown, ObservedAt: observedAt(),
		ProbeProfile: profile,
	}
	if result.Protocol == "" {
		result.Protocol = "tls"
	}
	if target.Host == "" || target.Port == 0 {
		result.Evidence.Error = errInvalidServiceTarget
		return result
	}
	if opts.Dialer == nil {
		opts.Dialer = &net.Dialer{}
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.TLSConfig != nil {
		config = opts.TLSConfig.Clone()
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = target.Host
	}
	config.ServerName = serverName

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := opts.Dialer.DialContext(probeCtx, transportTCP, net.JoinHostPort(target.Host, portString(target.Port)))
	if err != nil {
		result.Evidence.Error = boundedError(err)
		if connectionRefused(err) {
			result.State = observation.ServiceNotResponding
			result.Evidence.ResponseClass = responseTCPRefused
		}
		return result
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		result.Evidence.Error = boundedError(err)
		result.Evidence.ResponseClass = "tls_handshake_failed"
		return result
	}
	state := tlsConn.ConnectionState()
	result.State = observation.ServiceResponding
	result.Evidence.Address = conn.RemoteAddr().String()
	result.Evidence.ResponseClass = "tls_handshake"
	result.Evidence.TLSVersion = tls.VersionName(state.Version)
	result.Evidence.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.Evidence.SNI = serverName
	if len(state.PeerCertificates) > 0 {
		certificate := state.PeerCertificates[0]
		result.Evidence.CertificateSubject = certificate.Subject.String()
		result.Evidence.CertificateIssuer = certificate.Issuer.String()
		result.Evidence.CertificateExpiry = certificate.NotAfter.UTC().Format(time.RFC3339)
	}
	return result
}

func portString(port uint16) string {
	return fmt.Sprint(port)
}
