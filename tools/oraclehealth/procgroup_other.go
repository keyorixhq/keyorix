//go:build !unix

package main

import "os/exec"

// killGroupOnCancel is a no-op where process groups are unavailable; the tool
// relies on nice and is only meaningful on unix.
func killGroupOnCancel(*exec.Cmd) {}
