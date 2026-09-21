package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/adedayo/vantage/pkg/observation"
)

// StartTLSOptions configures one declared mail-protocol upgrade.
type StartTLSOptions struct {
	Dialer     Dialer
	Timeout    time.Duration
	Profile    string
	Now        func() time.Time
	TLSConfig  *tls.Config
	ServerName string
}

// StartTLS negotiates the explicitly named SMTP, IMAP or POP3 TLS transition.
// It sends only greetings, capability negotiation and the protocol's upgrade
// command; it never authenticates or sends message data.
func StartTLS(ctx context.Context, target Target, opts StartTLSOptions) observation.ServiceObservation {
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
	protocol := strings.ToLower(target.Protocol)
	result := observation.ServiceObservation{
		Host: target.Host, Port: target.Port, Transport: transportTCP,
		Protocol: protocol, Service: target.Service, Layer: observation.ServiceLayerStartTLS,
		State: observation.ServiceUnknown, ObservedAt: observedAt(),
		ProbeProfile: profile,
	}
	if protocol != protocolSMTP && protocol != protocolIMAP && protocol != protocolPOP3 {
		result.Evidence.Error = "unsupported starttls protocol"
		return result
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
	if deadline, ok := probeCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	reader := bufio.NewReader(conn)
	if err := negotiateStartTLS(reader, conn, protocol); err != nil {
		result.Evidence.Error = boundedError(err)
		result.Evidence.ResponseClass = "starttls_transition_failed"
		return result
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
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		result.Evidence.Error = boundedError(err)
		result.Evidence.ResponseClass = "starttls_handshake_failed"
		return result
	}

	state := tlsConn.ConnectionState()
	result.State = observation.ServiceResponding
	result.Evidence.Address = conn.RemoteAddr().String()
	result.Evidence.ResponseClass = "starttls_handshake"
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

func negotiateStartTLS(reader *bufio.Reader, conn net.Conn, protocol string) error {
	switch protocol {
	case "smtp":
		line, err := readProtocolLine(reader)
		if err != nil || !strings.HasPrefix(line, "220") {
			return fmt.Errorf("smtp greeting: %w", protocolError(err, line))
		}
		if _, err := fmt.Fprint(conn, "EHLO vantage.invalid\r\n"); err != nil {
			return err
		}
		if err := readSMTPResponse(reader, "250"); err != nil {
			return err
		}
		if _, err := fmt.Fprint(conn, "STARTTLS\r\n"); err != nil {
			return err
		}
		line, err = readProtocolLine(reader)
		if err != nil || !strings.HasPrefix(line, "220") {
			return fmt.Errorf("smtp starttls response: %w", protocolError(err, line))
		}
		return nil
	case "imap":
		line, err := readProtocolLine(reader)
		if err != nil || !strings.HasPrefix(line, "*") {
			return fmt.Errorf("imap greeting: %w", protocolError(err, line))
		}
		if _, err := fmt.Fprint(conn, "a001 CAPABILITY\r\n"); err != nil {
			return err
		}
		capabilities := ""
		for {
			line, err = readProtocolLine(reader)
			if err != nil {
				return err
			}
			capabilities += " " + line
			if strings.HasPrefix(line, "a001 ") {
				break
			}
		}
		if !strings.Contains(strings.ToUpper(capabilities), " STARTTLS") {
			return fmt.Errorf("imap server does not advertise STARTTLS")
		}
		if _, err := fmt.Fprint(conn, "a002 STARTTLS\r\n"); err != nil {
			return err
		}
		line, err = readProtocolLine(reader)
		if err != nil || !strings.HasPrefix(line, "a002 OK") {
			return fmt.Errorf("imap starttls response: %w", protocolError(err, line))
		}
		return nil
	case "pop3":
		line, err := readProtocolLine(reader)
		if err != nil || !strings.HasPrefix(line, "+OK") {
			return fmt.Errorf("pop3 greeting: %w", protocolError(err, line))
		}
		if _, err := fmt.Fprint(conn, "STLS\r\n"); err != nil {
			return err
		}
		line, err = readProtocolLine(reader)
		if err != nil || !strings.HasPrefix(line, "+OK") {
			return fmt.Errorf("pop3 starttls response: %w", protocolError(err, line))
		}
		return nil
	default:
		return fmt.Errorf("unsupported starttls protocol %q", protocol)
	}
}

func readSMTPResponse(reader *bufio.Reader, code string) error {
	for {
		line, err := readProtocolLine(reader)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, code) {
			return fmt.Errorf("unexpected SMTP response %q", line)
		}
		if len(line) < 4 || line[3] == ' ' {
			return nil
		}
	}
}

func readProtocolLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if len(line) > 4096 {
		return "", fmt.Errorf("protocol line exceeds 4096 bytes")
	}
	return strings.TrimSpace(line), err
}

func protocolError(err error, line string) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("unexpected response %q", line)
}
