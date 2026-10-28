//go:build darwin

package crypto

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY returns the master and slave ends of a new pseudo-terminal. Test support
// for the terminal-only branches of readPassphraseStdin (no pty dependency in go.mod).
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*os.File, *os.File, error) {
		_ = master.Close()
		return nil, nil, err
	}
	fd := master.Fd()
	if err := unix.IoctlSetInt(int(fd), unix.TIOCPTYGRANT, 0); err != nil {
		return fail(fmt.Errorf("grant pty: %w", err))
	}
	if err := unix.IoctlSetInt(int(fd), unix.TIOCPTYUNLK, 0); err != nil {
		return fail(fmt.Errorf("unlock pty: %w", err))
	}
	var name [128]byte
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); errno != 0 { //nolint:gosec // fixed-size buffer the ioctl fills
		return fail(fmt.Errorf("pty name: %w", errno))
	}
	n := 0
	for n < len(name) && name[n] != 0 {
		n++
	}
	slave, err = os.OpenFile(string(name[:n]), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return fail(err)
	}
	return master, slave, nil
}
