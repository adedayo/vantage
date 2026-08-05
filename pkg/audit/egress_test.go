package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEveryCheckDeclaresAnEgressProfile is the conformance check that makes an
// upgrade fail closed. A check added without a declared profile cannot be
// reasoned about by a deployment policy, so it must fail the build rather than
// run under permissions nobody granted it.
func TestEveryCheckDeclaresAnEgressProfile(t *testing.T) {
	for _, d := range Descriptions() {
		assert.Truef(t, d.Egress.Declared(),
			"check %q does not declare an egress profile", d.Name)
		require.NoErrorf(t, d.Egress.validate(d.Name),
			"check %q has an incoherent egress profile", d.Name)
	}
}

// TestEveryThirdPartyServiceIsNamedAndReachable asserts that a check may only
// name a service the package declares an endpoint for. This is what stops a
// new external dependency arriving unannounced: naming an unknown service is a
// validation failure, and adding a known one requires editing the endpoint
// table, which is a reviewable act.
func TestEveryThirdPartyServiceIsNamedAndReachable(t *testing.T) {
	for _, d := range Descriptions() {
		for _, s := range d.Egress.ThirdParty {
			assert.Truef(t, s.Known(),
				"check %q names undeclared third-party service %q", d.Name, s)
			assert.NotEmptyf(t, s.Endpoints(),
				"third-party service %q has no endpoints", s)
		}
	}
}

// TestIntrusiveChecksAreExcludedFromDefaultProfiles pins the guarantee that an
// intrusive check never runs without being asked for. The default profile is
// standard, so an intrusive check appearing there would run for every user who
// never chose it.
func TestIntrusiveChecksAreExcludedFromDefaultProfiles(t *testing.T) {
	defaults := map[string]bool{}
	for _, name := range profileMembers[ProfileStandard] {
		defaults[name] = true
	}
	for _, name := range profileMembers[ProfileQuick] {
		defaults[name] = true
	}

	for _, d := range Descriptions() {
		if d.Egress.Intrusive {
			assert.Falsef(t, defaults[d.Name],
				"intrusive check %q must not be in a default profile", d.Name)
		}
	}
}

// TestAXFRIsDeclaredIntrusive pins the specific case the README documents, so
// that a refactor cannot quietly downgrade it.
func TestAXFRIsDeclaredIntrusive(t *testing.T) {
	c, ok := Lookup("axfr")
	require.True(t, ok, "the axfr check should be registered")

	e := c.Describe().Egress
	assert.True(t, e.Intrusive, "axfr must be declared intrusive")
	assert.True(t, e.TargetNameservers, "axfr queries the target's nameservers directly")
	assert.Empty(t, e.ThirdParty, "axfr contacts no third party")
}

// TestChecksQueryingNameserversDirectlyDeclareIt pins the four checks the
// README names as going straight to the authoritative servers. A consumer
// excludes them by this property, never by name, so the property has to be
// accurate.
func TestChecksQueryingNameserversDirectlyDeclareIt(t *testing.T) {
	for _, name := range []string{"wild", "ns", "tko", "axfr"} {
		c, ok := Lookup(name)
		require.Truef(t, ok, "check %q should be registered", name)
		assert.Truef(t, c.Describe().Egress.TargetNameservers,
			"check %q queries the target's nameservers and must declare it", name)
	}
}

// TestNetworksAreDerivedFromTheProfile asserts the derivation, which is what
// guarantees the coarse classification cannot contradict the detailed one.
func TestNetworksAreDerivedFromTheProfile(t *testing.T) {
	cases := map[string]struct {
		profile EgressProfile
		want    []Network
	}{
		"resolver only": {EgressProfile{Resolver: true}, []Network{NetworkDNS}},
		"nameservers count as DNS": {
			EgressProfile{TargetNameservers: true}, []Network{NetworkDNS},
		},
		"target https": {
			EgressProfile{Resolver: true, TargetHTTPS: true},
			[]Network{NetworkDNS, NetworkHTTPS},
		},
		"third party": {
			EgressProfile{Resolver: true, ThirdParty: []ThirdPartyService{ServiceCRTSh}},
			[]Network{NetworkDNS, NetworkThirdParty},
		},
		"offline": {EgressProfile{Offline: true}, []Network{NetworkNone}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.profile.Networks())
		})
	}
}

// TestUndeclaredProfileIsRejected asserts the zero value is refused. A profile
// that says nothing must never be read as a claim of no egress.
func TestUndeclaredProfileIsRejected(t *testing.T) {
	err := EgressProfile{}.validate("silent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not declare its egress profile")
}

// TestOfflineProfileCannotAlsoDeclareEgress asserts the contradiction is caught.
func TestOfflineProfileCannotAlsoDeclareEgress(t *testing.T) {
	err := EgressProfile{Offline: true, Resolver: true}.validate("confused")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offline but also declares egress")
}

// TestUnknownThirdPartyServiceIsRejected asserts a service invented at a call
// site cannot pass validation.
func TestUnknownThirdPartyServiceIsRejected(t *testing.T) {
	err := EgressProfile{
		Resolver:   true,
		ThirdParty: []ThirdPartyService{"some-new-service"},
	}.validate("newcomer")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown third-party service")
}

// TestServiceForURLResolvesDeclaredEndpoints asserts the inverse mapping a
// scope-guarding transport relies on to name the service a request was
// permitted under.
func TestServiceForURLResolvesDeclaredEndpoints(t *testing.T) {
	s, ok := ServiceForURL("https://crt.sh/?q=example.com&output=json")
	require.True(t, ok)
	assert.Equal(t, ServiceCRTSh, s)

	s, ok = ServiceForURL("https://ip-ranges.amazonaws.com/ip-ranges.json")
	require.True(t, ok)
	assert.Equal(t, ServiceAWSRanges, s)

	// An endpoint nobody declared is not attributable, and a default-deny
	// transport therefore refuses it.
	_, ok = ServiceForURL("https://evil.example.com/ranges.json")
	assert.False(t, ok)
}

// TestEveryDeclaredServiceIsUsedBySomeCheck stops the endpoint table becoming
// a list of permissions granted for checks that no longer exist.
func TestEveryDeclaredServiceIsUsedBySomeCheck(t *testing.T) {
	used := map[ThirdPartyService]bool{}
	for _, d := range Descriptions() {
		for _, s := range d.Egress.ThirdParty {
			used[s] = true
		}
	}
	for _, s := range ThirdPartyServices() {
		assert.Truef(t, used[s],
			"service %q is declared but no check uses it", s)
	}
}
