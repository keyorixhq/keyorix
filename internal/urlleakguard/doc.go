// Package urlleakguard holds a repo-wide static guard (test-only): no log call
// or error constructor may format a configured endpoint, URL or DSN verbatim.
// See urlleakguard_test.go for what it does and does not recognise.
package urlleakguard
