//go:build unix

package securefile

import "syscall"

// noFollowFlag makes every write in this package refuse to traverse a symlink at the
// final path component -- an attacker who plants a symlink at an operator-supplied
// output path cannot redirect the write. Mirrors cli/internal/credstore's identical
// flag/rationale for the credentials file.
const noFollowFlag = syscall.O_NOFOLLOW
