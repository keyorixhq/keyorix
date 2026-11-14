//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// killGroupOnCancel starts cmd in its own process group and, when its context
// is cancelled, kills the whole group (nice, go, and the test binary).
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
