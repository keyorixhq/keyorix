// scim_bool.go — the one decoder for a SCIM boolean attribute (`active`).
//
// RFC 7643 §2.3.2 says a SCIM boolean is a JSON true/false, but Microsoft Entra ID
// sends `{"op":"Replace","path":"active","value":"False"}`: the string form. A strict
// json.Unmarshal into a bool failed on it, `active` stayed nil, UpdateSCIMUser ran
// with nothing to change and PatchUser answered 200, so the IdP believed a terminated
// user was deactivated while the account, its sessions and PATs stayed live.
//
// Every SCIM user body that carries `active` (PATCH with path "active", the path-less
// PATCH object form, PUT and POST) decodes it here. A JSON bool or the strings
// "true"/"false" in any case are accepted; anything else (another string, a number,
// null, an object, a missing value) is errSCIMInvalidBool, which the handlers answer
// with 400 invalidValue. A present-but-unparseable `active` never answers 200.
package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// errSCIMInvalidBool: a SCIM boolean attribute was present but is neither a JSON bool
// nor the string "true"/"false".
var errSCIMInvalidBool = errors.New("active must be a boolean (true or false)")

// parseSCIMBool decodes a SCIM boolean value tolerantly (see the file comment).
func parseSCIMBool(raw json.RawMessage) (bool, error) {
	v := bytes.TrimSpace(raw)
	switch string(v) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	var s string
	if len(v) > 0 && v[0] == '"' && json.Unmarshal(v, &s) == nil {
		switch {
		case strings.EqualFold(strings.TrimSpace(s), "true"):
			return true, nil
		case strings.EqualFold(strings.TrimSpace(s), "false"):
			return false, nil
		}
	}
	return false, errSCIMInvalidBool
}

// scimBool is a SCIM boolean attribute in a decoded body. It is a value field, not a
// pointer, on purpose: encoding/json then calls UnmarshalJSON for an explicit null
// too (a pointer field would be silently set to nil), so a present `"active":null`
// is refused like any other unparseable value. An absent attribute leaves present
// false.
type scimBool struct {
	present bool
	value   bool
}

// UnmarshalJSON implements json.Unmarshaler through parseSCIMBool.
func (b *scimBool) UnmarshalJSON(data []byte) error {
	v, err := parseSCIMBool(data)
	if err != nil {
		return err
	}
	*b = scimBool{present: true, value: v}
	return nil
}

// ptr returns the attribute as the *bool core takes (nil when absent).
func (b scimBool) ptr() *bool {
	if !b.present {
		return nil
	}
	v := b.value
	return &v
}

// writeSCIMDecodeError answers a body that failed to decode: 400 invalidValue for an
// unparseable `active`, the generic 400 otherwise.
func writeSCIMDecodeError(w http.ResponseWriter, err error, generic string) {
	if errors.Is(err, errSCIMInvalidBool) {
		scimErrorTyped(w, http.StatusBadRequest, scimTypeInvalidValue, errSCIMInvalidBool.Error())
		return
	}
	scimError(w, http.StatusBadRequest, generic)
}
