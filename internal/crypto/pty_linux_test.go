//go:build linux

package crypto

import (
	"fmt"
	"os"

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
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return fail(fmt.Errorf("unlock pty: %w", err))
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return fail(fmt.Errorf("pty number: %w", err))
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return fail(err)
	}
	return master, slave, nil
}
