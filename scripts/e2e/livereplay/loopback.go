package livereplay

import (
	"fmt"
	"net"
	"net/url"
)

// validateLoopbackURL refuses an http(s) URL whose host is not loopback. The
// system under test is always a throwaway server on this machine.
func validateLoopbackURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("livereplay: invalid base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("livereplay: base URL scheme %q is not http/https", u.Scheme)
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("livereplay: base URL host %q is not loopback: the replay only runs against a server on this machine", host)
}
