package vantage

import "errors"

// Sentinel errors for the failure classes an embedding consumer must be able to
// act on programmatically.
//
// These exist because classifying a failure by matching the wording of its
// message is unsafe in exactly the situation that matters most. A consumer that
// mistakes "we could not check" for "the control is absent" reports a missing
// control that may well be present, and rewording a message would silently
// change that verdict. Wrapping these sentinels makes the classification part
// of the contract, so the message stays free to change.
//
// Callers should test with errors.Is rather than comparing values, since these
// are wrapped with context as they propagate.
var (
	// ErrResolverUnreachable means no resolver could be reached to answer the
	// query. It says nothing about whether the record exists, which is why it
	// must never be collapsed into ErrNotFound.
	ErrResolverUnreachable = errors.New("error: resolver unreachable")

	// ErrNetworkDisabled means the check needed egress that the caller
	// withheld, typically via --no-network. The assessment did not happen and
	// no conclusion about the target may be drawn from it.
	ErrNetworkDisabled = errors.New("error: network disabled")

	// ErrOutOfScope means the caller's own policy refused the egress. It is
	// raised by a consumer wrapping Resolver or an HTTP transport in a scope
	// guard, and is distinct from a network failure: nothing was attempted,
	// and nothing is wrong with the target or the network.
	//
	// Vantage itself never returns this. It is declared here so that a scope
	// guard and the classifier agree on the concept, rather than each
	// inventing its own and meeting only through a substring match.
	ErrOutOfScope = errors.New("error: out of scope")

	// ErrInvalidRecord means a record was retrieved but could not be parsed.
	// The record is present, so this is a finding about the target rather than
	// a failure of the tool.
	ErrInvalidRecord = errors.New("error: invalid record")
)
