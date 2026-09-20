package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNamesListRendersReadablePhrases(t *testing.T) {
	assert.Equal(t, "", namesList(nil))
	assert.Equal(t, "`a.example`", namesList([]string{"a.example"}))
	assert.Equal(t, "`a.example` and `b.example`",
		namesList([]string{"a.example", "b.example"}))
	assert.Equal(t, "`a.example`, `b.example` and `c.example`",
		namesList([]string{"a.example", "b.example", "c.example"}))
}

// Blank entries would render as an empty pair of backticks, which reads as a
// missing name rather than as no name at all.
func TestNamesListSkipsBlanks(t *testing.T) {
	assert.Equal(t, "`a.example` and `b.example`",
		namesList([]string{"a.example", "  ", "b.example", ""}))
}

// Past the cap the sentence has to stop naming and start counting, or it
// becomes the wall of text it was written to replace.
func TestNamesListTruncatesLongLists(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e", "f", "g"}
	assert.Equal(t, "`a`, `b`, `c`, `d`, `e` and 2 others", namesList(items))

	assert.Equal(t, "`a`, `b`, `c`, `d`, `e` and 1 other",
		namesList([]string{"a", "b", "c", "d", "e", "f"}))
}

func TestBrokenTargetNameStripsMechanismPrefix(t *testing.T) {
	assert.Equal(t, "spf.example.com", brokenTargetName("include:spf.example.com"))
	assert.Equal(t, "spf.example.com", brokenTargetName("redirect=spf.example.com"))
	assert.Equal(t, "spf.example.com", brokenTargetName("spf.example.com"))
}
