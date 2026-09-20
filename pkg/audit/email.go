package audit

import (
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/observation"
)

// presenceOf converts "was a record retrieved" into the three-valued presence
// a consumer reads.
//
// Only two of the three values are ever produced here, and that is correct: a
// check reaching this point has had an answer from the resolver. The third,
// undetermined, belongs to a check that failed outright — which returns an
// error and no observation at all, so there is nothing for it to label. The
// consumer supplies it when it sees a failed check, because only the consumer
// knows which checks it asked for.
func presenceOf(found bool) observation.Presence {
	if found {
		return observation.PresencePublished
	}
	return observation.PresenceAbsent
}

// adjacentObservation builds the observation for one of the records
// surrounding the core three — MTA-STS, TLS-RPT, BIMI, CAA.
//
// They are given a common shape because a consumer needs to tier them as a
// group. Their absence is worth reporting and is never as consequential as a
// missing DMARC policy, and a consumer that had to recognise each by name
// would silently fail to tier a record added later.
func adjacentObservation(domain, kind string, found bool, detail string) *finding.Observation {
	return &finding.Observation{Email: &observation.Email{
		Domain: domain,
		Adjacent: &observation.AdjacentRecord{
			Kind:     kind,
			Presence: presenceOf(found),
			Detail:   detail,
		},
	}}
}
