package pgfault

import (
	"strconv"
	"strings"
)

func itoa(i int) string { return strconv.Itoa(i) }

// parsePC parses a "pc-<i>" description back to its index.
func parsePC(d string) (int, bool) {
	s, ok := strings.CutPrefix(d, "pc-")
	if !ok {
		return 0, false
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return i, true
}
