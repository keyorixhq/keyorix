package cmd

import (
	"encoding/json"
	"strings"

	types "github.com/oapi-codegen/runtime/types"
)

// cliEmailAddress turns an --email style flag value into the generated client's
// Email type, refusing a value the client would not send as typed.
//
// The oapi-codegen runtime (checked up to v1.9.1) parses an Email with
// net/mail and keeps only m.Address. For a quoted local part ("a b"@example.com)
// that is the unquoted a b@example.com, which MarshalJSON itself then rejects:
// a value read back from the server cannot be sent again, and a quoted value typed
// on the command line is silently rewritten into a different address. A display
// name ("Bob <bob@example.com>") is dropped the same way. The runtime is vendored
// third-party code, so the check lives here: one error that names the flag, raised
// before anything is sent. The value is not echoed back.
//
// hint is appended to the "not a valid email address" error (may be empty).
func cliEmailAddress(flag, value, hint string) (types.Email, error) {
	value = strings.TrimSpace(value)
	e := types.Email(value)
	b, err := e.MarshalJSON()
	if err != nil {
		return "", usageErrorf("--%s is not a valid email address.%s", flag, hint)
	}
	var sent string
	if err := json.Unmarshal(b, &sent); err != nil || sent != value {
		return "", usageErrorf("--%s must be a plain name@domain.tld address: a quoted local part or a display name "+
			"cannot be sent unchanged by this client.%s", flag, hint)
	}
	return e, nil
}
