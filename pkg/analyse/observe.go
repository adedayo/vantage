package analyse

import (
	"strings"

	"github.com/adedayo/vantage/pkg/observation"
)

// Observation converts parsed DMARC tags into the structured form a consumer
// reads.
//
// It is a method on the parse result rather than a second parser so that the
// facts a consumer acts on and the facts this package raises findings from are
// necessarily the same facts. Two parsers eventually disagree, and when they
// do, one part of a system reports a domain as protected while another reports
// it as exposed — with nothing to indicate which is right.
func (p DMARCPolicy) Observation(recordCount int) observation.DMARC {
	obs := observation.DMARC{
		Presence:           observation.PresencePublished,
		Record:             p.Raw,
		Policy:             p.Policy,
		SubdomainPolicy:    p.Subdomain,
		Percent:            p.Percent,
		AlignmentDKIM:      p.ADKIM,
		AlignmentSPF:       p.ASPF,
		AggregateReporting: len(p.RUA) > 0,
		RecordCount:        recordCount,
		Valid:              p.Valid,
	}
	if recordCount == 0 {
		obs.Presence = observation.PresenceAbsent
	}
	return obs
}

// AbsentDMARC is the observation for a domain publishing no DMARC record.
//
// Named rather than constructed inline at each call site, because "absent" is
// a specific claim — the resolver answered and there was nothing there — and
// giving it one spelling keeps it from being confused with a zero value that
// merely means nothing was recorded.
func AbsentDMARC() observation.DMARC {
	return observation.DMARC{Presence: observation.PresenceAbsent, Percent: 100}
}

// DKIMObservation summarises what probing selectors established.
//
// examined is every selector queried, not only those that answered. The
// difference is the whole point: a consumer that sees three selectors found
// out of thirteen tried knows something quite different from one told only
// that three were found.
func DKIMObservation(examined []string, keys []DKIMKey, probed bool) observation.DKIM {
	obs := observation.DKIM{
		SelectorsExamined: examined,
		Probed:            probed,
	}
	for _, k := range keys {
		obs.SelectorsFound = append(obs.SelectorsFound, k.Selector)
		// Usable is defined exactly as DKIM defines it, so the count and the
		// findings cannot tell different stories about the same key. Test mode
		// is reported as its own finding rather than deducted here.
		if k.Valid && !k.Revoked {
			obs.UsableKeys++
		}
	}
	return obs
}

// AdjacentObservation describes one of the records surrounding the core three.
//
// present is passed explicitly rather than inferred from detail being
// non-empty, because several of these records are meaningful while carrying no
// detail worth extracting, and inferring absence from an empty string would
// report those as missing.
func AdjacentObservation(kind string, present bool, detail string) observation.AdjacentRecord {
	rec := observation.AdjacentRecord{
		Kind:     strings.ToLower(kind),
		Presence: observation.PresenceAbsent,
		Detail:   detail,
	}
	if present {
		rec.Presence = observation.PresencePublished
	}
	return rec
}
