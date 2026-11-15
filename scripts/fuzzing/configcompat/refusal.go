package configcompat

import (
	"regexp"
	"strings"
)

// Canary is a value the fuzzer plants as a secret-bearing config VALUE. It must
// never appear in a load/validate error string — except where an error echoes a
// misspelt KEY name back to the operator, which is the whole point of that
// message and not a secret disclosure.
const Canary = "cnrycompat0123456789"

// keyEcho matches the parts of a refusal that legitimately repeat a key NAME
// taken from the file. This is the configspace masked-refusal signature idea,
// reused (not copied): the two shapes keyorix's loader actually emits — yaml.v3
// strict-decode ("field X not found in type ...") and the loader's own
// describeUnknownKeys rewrite ("unknown key \"X\" ..."). Naming the offending
// key is the required fail-closed behaviour (I1), so a canary the fuzzer typed
// AS a key name is masked before the canary-leak check; a canary that leaks as a
// VALUE is still caught.
var keyEcho = regexp.MustCompile(`unknown key "[^"]*"|field \S+ not found in type [\w.]+`)

// namesAKey reports whether a refusal verdict names at least one key — i.e.
// matches the masked refusal signature. A keyed file that is refused with a
// message naming no key is the fail-closed violation I1 forbids.
func namesAKey(verdict string) bool {
	return keyEcho.MatchString(verdict)
}

// leaksCanary reports whether verdict discloses the canary outside a key echo.
func leaksCanary(verdict string) bool {
	return strings.Contains(keyEcho.ReplaceAllString(verdict, "-"), Canary)
}

// isRefusal reports whether a verdict string is a load/validate refusal (vs the
// empty-string "accepted" verdict).
func isRefusal(verdict string) bool { return verdict != "" }
