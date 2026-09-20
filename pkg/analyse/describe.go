package analyse

import (
	"strconv"
	"strings"
)

// This file holds the helpers that let a finding say which item is at fault.
//
// A catalogue description has to be written before anything is observed, so it
// can only speak in generalities: "a nameserver", "an include target", "one or
// more hosts". The offending item is always in the evidence, but evidence is a
// flat list of key/value pairs, and when one of those values is a whole SPF
// record or DKIM key the item that actually needs fixing ends up buried behind
// it. A reader is then told a problem exists and left to find it.
//
// The remedy is a sentence, appended to the catalogue description, that names
// the item. It changes no evidence and no finding ID, so anything matching on
// those is unaffected; it only means the first thing read is the thing to fix.

// maxNamedItems caps how many items a description will list.
//
// The sentence exists to point at the fault, and a sentence carrying forty
// hostnames points at nothing — it is the wall of evidence it was meant to
// replace. Past the cap the description gives a count and defers to the
// evidence, which still holds every name.
const maxNamedItems = 5

// namesList renders items as a quoted, human-readable list: "`a`", "`a` and
// `b`", "`a`, `b` and `c`". Beyond maxNamedItems it truncates with a count, so
// that the sentence stays readable regardless of how large the estate is.
func namesList(items []string) string {
	var kept []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			kept = append(kept, "`"+item+"`")
		}
	}

	switch len(kept) {
	case 0:
		return ""
	case 1:
		return kept[0]
	}

	if len(kept) > maxNamedItems {
		remainder := len(kept) - maxNamedItems
		noun := " others"
		if remainder == 1 {
			noun = " other"
		}
		return strings.Join(kept[:maxNamedItems], ", ") + " and " +
			strconv.Itoa(remainder) + noun
	}

	return strings.Join(kept[:len(kept)-1], ", ") + " and " + kept[len(kept)-1]
}
