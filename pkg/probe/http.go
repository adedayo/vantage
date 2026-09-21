package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/observation"
)

// HTTPDoer is injectable so a consumer can enforce scope at the transport.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// HTTPOptions configures a bounded, read-only HTTP request.
type HTTPOptions struct {
	Client  HTTPDoer
	Timeout time.Duration
	Profile string
	Now     func() time.Time
}

// HTTP performs one GET request to the declared endpoint. The response body
// is bounded and discarded; only response metadata enters the observation.
func HTTP(ctx context.Context, target Target, opts HTTPOptions) observation.ServiceObservation {
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
		Protocol: target.Protocol, Service: target.Service, Layer: observation.ServiceLayerHTTP,
		State: observation.ServiceUnknown, ObservedAt: observedAt(),
		ProbeProfile: profile,
	}
	if result.Protocol == "" {
		result.Protocol = protocolHTTP
	}
	if target.Host == "" || target.Port == 0 {
		result.Evidence.Error = errInvalidServiceTarget
		return result
	}
	scheme := protocolHTTP
	if result.Protocol == protocolHTTPS {
		scheme = protocolHTTPS
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet,
		(&url.URL{Scheme: scheme, Host: net.JoinHostPort(target.Host, fmt.Sprint(target.Port)), Path: "/"}).String(), nil)
	if err != nil {
		result.Evidence.Error = boundedError(err)
		if connectionRefused(err) {
			result.State = observation.ServiceNotResponding
			result.Evidence.ResponseClass = responseTCPRefused
		}
		return result
	}
	client := opts.Client
	if client == nil {
		client = vantage.NewHTTPClient(vantage.HTTPOptions{Timeout: timeout})
	}
	response, err := client.Do(request)
	if err != nil {
		result.Evidence.Error = boundedError(err)
		return result
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	result.State = observation.ServiceResponding
	result.Evidence.ResponseClass = "http_response"
	result.Evidence.HTTPStatus = response.StatusCode
	result.Evidence.Server = response.Header.Get("Server")
	return result
}
