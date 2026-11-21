package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// validateLoopbackHost refuses a host or host:port that is not loopback. Every
// server this tool talks to is a throwaway child process on this machine; a
// non-loopback target means a misconfigured -upstream or a corrupted URL, and
// the tool must not send credentials or seed data to it.
func validateLoopbackHost(hostport string) error {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("sdkdiff: host %q is not loopback: this tool only talks to throwaway servers on this machine", host)
}

// validateLoopbackURL refuses an http(s) URL whose host is not loopback.
func validateLoopbackURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("sdkdiff: invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("sdkdiff: URL scheme %q is not http/https", u.Scheme)
	}
	return validateLoopbackHost(u.Host)
}

// maxRedirects bounds the redirect chain loopbackClient follows.
const maxRedirects = 10

// loopbackClient follows redirects only while they stay on loopback, so a 3xx
// from the throwaway server cannot bounce a request to another host.
var loopbackClient = &http.Client{
	Timeout: 60 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("sdkdiff: stopped after %d redirects", maxRedirects)
		}
		return validateLoopbackURL(req.URL.String())
	},
}
