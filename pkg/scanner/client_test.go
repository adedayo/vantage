package scanner_test

import (
	"time"

	vantage "github.com/adedayo/vantage/pkg"
)

// testResolver is the default client for scanner tests.
//
// Tests exercising a mock zone build their own client pointed at it. The rest
// use this one, whose short budgets keep a test that is meant to observe a
// failure from waiting out the production defaults.
//
// The WithServer variants take an explicit address and use this only for its
// timeouts, which is why a client with no reachable servers is still the right
// default here.
var testResolver vantage.Resolver = vantage.NewClient(vantage.Config{
	Servers:      []string{"127.0.0.1:1"},
	QueryTimeout: 200 * time.Millisecond,
	TotalTimeout: 2 * time.Second,
})
