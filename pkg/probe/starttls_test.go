package probe_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adedayo/vantage/pkg/observation"
	"github.com/adedayo/vantage/pkg/probe"
)

func TestStartTLSNegotiatesDeclaredMailProtocols(t *testing.T) {
	for _, protocol := range []string{"smtp", "imap", "pop3"} {
		t.Run(protocol, func(t *testing.T) {
			certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			config := certificateServer.TLS.Clone()
			certificateServer.Close()

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer listener.Close()
			serverErr := make(chan error, 1)
			go serveStartTLS(listener, config, protocol, serverErr)

			host, port := splitAddress(t, listener.Addr().String())
			result := probe.StartTLS(context.Background(), probe.Target{
				Host: host, Port: port, Protocol: protocol,
			}, probe.StartTLSOptions{
				TLSConfig: &tls.Config{InsecureSkipVerify: true},
				Timeout:   time.Second,
			})

			if result.State != observation.ServiceResponding {
				t.Fatalf("state = %q, want responding: %+v", result.State, result)
			}
			if result.Evidence.ResponseClass != "starttls_handshake" || result.Evidence.TLSVersion == "" {
				t.Fatalf("missing STARTTLS evidence: %+v", result.Evidence)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}

func serveStartTLS(listener net.Listener, config *tls.Config, protocol string, result chan<- error) {
	conn, err := listener.Accept()
	if err != nil {
		result <- err
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	write := func(message string) error {
		_, err := fmt.Fprint(conn, message)
		return err
	}
	read := func(want string) error {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) != want {
			return fmt.Errorf("received %q, want %q", strings.TrimSpace(line), want)
		}
		return nil
	}

	switch protocol {
	case "smtp":
		if err = write("220 ready\r\n"); err == nil {
			err = read("EHLO vantage.invalid")
			if err == nil {
				err = write("250-test\r\n250 STARTTLS\r\n")
			}
			if err == nil {
				err = read("STARTTLS")
			}
			if err == nil {
				err = write("220 go ahead\r\n")
			}
		}
	case "imap":
		if err = write("* OK ready\r\n"); err == nil {
			err = read("a001 CAPABILITY")
			if err == nil {
				err = write("* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK done\r\n")
			}
			if err == nil {
				err = read("a002 STARTTLS")
			}
			if err == nil {
				err = write("a002 OK begin\r\n")
			}
		}
	case "pop3":
		if err = write("+OK ready\r\n"); err == nil {
			err = read("STLS")
			if err == nil {
				err = write("+OK begin\r\n")
			}
		}
	}
	if err != nil {
		result <- err
		return
	}
	tlsConn := tls.Server(conn, config)
	result <- tlsConn.Handshake()
}
