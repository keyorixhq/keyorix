package httpx

import (
	"net/http"
	"strconv"
)

// ParseOptionalUintQuery parses an optional uint query parameter; returns (nil, nil)
// when absent and (nil, err) when present but not a valid uint.
func ParseOptionalUintQuery(r *http.Request, key string) (*uint, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return nil, nil
	}
	id, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return nil, err
	}
	uid := uint(id)
	return &uid, nil
}
