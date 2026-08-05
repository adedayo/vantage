package vantage

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetTimeouts restores the default timeout configuration after a test.
func TestTimeoutDefaults(t *testing.T) {
	c := NewClient(Config{})
	assert.Equal(t, DefaultQueryTimeout, c.QueryTimeout())
	assert.Equal(t, DefaultTotalTimeout, c.TotalTimeout())
	assert.Less(t, DefaultQueryTimeout, DefaultTotalTimeout,
		"a single attempt must be shorter than the overall budget for failover to work")
}

func TestClientConfigOverridesTimeoutDefaults(t *testing.T) {
	c := NewClient(Config{QueryTimeout: 250 * time.Millisecond, TotalTimeout: 3 * time.Second})
	assert.Equal(t, 250*time.Millisecond, c.QueryTimeout())
	assert.Equal(t, 3*time.Second, c.TotalTimeout())

	// A non-positive value means "unset", so the default applies.
	c = NewClient(Config{QueryTimeout: 0, TotalTimeout: -1})
	assert.Equal(t, DefaultQueryTimeout, c.QueryTimeout())
	assert.Equal(t, DefaultTotalTimeout, c.TotalTimeout())
}

func TestTimeoutsFromEnvironment(t *testing.T) {
	t.Setenv(QueryTimeoutEnvVar, "750ms")
	t.Setenv(TotalTimeoutEnvVar, "20s")

	c := NewClient(ConfigFromEnv())
	assert.Equal(t, 750*time.Millisecond, c.QueryTimeout())
	assert.Equal(t, 20*time.Second, c.TotalTimeout())

	// An explicit value takes precedence over the environment, which is what
	// lets a caller layer flags on top of ConfigFromEnv.
	cfg := ConfigFromEnv()
	cfg.QueryTimeout = 100 * time.Millisecond
	assert.Equal(t, 100*time.Millisecond, NewClient(cfg).QueryTimeout())
}

func TestInvalidEnvironmentTimeoutsFallBackToDefaults(t *testing.T) {
	t.Setenv(QueryTimeoutEnvVar, "not-a-duration")
	t.Setenv(TotalTimeoutEnvVar, "-5s")
	assert.Equal(t, DefaultQueryTimeout, NewClient(ConfigFromEnv()).QueryTimeout())
	assert.Equal(t, DefaultTotalTimeout, NewClient(ConfigFromEnv()).TotalTimeout())
}

func TestAttemptTimeoutIsCappedByRemainingBudget(t *testing.T) {
	c := NewClient(Config{QueryTimeout: 2 * time.Second})

	assert.Equal(t, 2*time.Second, c.attemptTimeout(5*time.Second),
		"plenty of budget left: use the full query timeout")
	assert.Equal(t, 300*time.Millisecond, c.attemptTimeout(300*time.Millisecond),
		"little budget left: never overrun the overall deadline")
}

func TestBudgetHonoursTheSoonerOfContextAndTotalTimeout(t *testing.T) {
	c := NewClient(Config{TotalTimeout: 10 * time.Second})

	remaining, err := c.budget(context.Background())
	require.NoError(t, err)
	assert.InDelta(t, float64(10*time.Second), float64(remaining), float64(time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	remaining, err = c.budget(ctx)
	require.NoError(t, err)
	assert.LessOrEqual(t, remaining, time.Second)

	expired, cancelExpired := context.WithTimeout(context.Background(), -time.Second)
	defer cancelExpired()
	_, err = c.budget(expired)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestFastFailoverToWorkingResolver is the behavioural guarantee: a blackholed
// resolver must be abandoned after the (short) query timeout so the next
// resolver still answers well inside the overall budget.
func TestFastFailoverToWorkingResolver(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("failover.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "failover.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"v=spf1 -all"},
		})
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	// 192.0.2.0/24 (TEST-NET-1) is guaranteed unroutable.
	client := NewClient(Config{
		Servers:      []string{"192.0.2.1", "192.0.2.2", addr},
		QueryTimeout: 200 * time.Millisecond,
		TotalTimeout: 5 * time.Second,
	})

	start := time.Now()
	txts, err := LookupTXT(context.Background(), client, "failover.test")
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, []string{"v=spf1 -all"}, txts)
	assert.Less(t, elapsed, 2*time.Second,
		"two dead resolvers should be skipped quickly, not stall the lookup")
}

// TestTotalTimeoutBoundsFailover ensures the overall budget is respected even
// when every resolver is unreachable.
func TestTotalTimeoutBoundsFailover(t *testing.T) {
	client := NewClient(Config{
		Servers:      []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"},
		QueryTimeout: 200 * time.Millisecond,
		TotalTimeout: 600 * time.Millisecond,
	})

	start := time.Now()
	_, err := LookupTXT(context.Background(), client, "unreachable.test")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error: dns query failed")
	assert.Less(t, elapsed, 2*time.Second, "the total timeout must bound the whole lookup")
}
