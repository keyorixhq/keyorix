//go:build unix

package credstore

import "syscall"

// noFollowFlag makes both Save and Load refuse to traverse a symlink at the final path
// component -- an attacker who plants a symlink at the credentials path (e.g. in a shared
// or predictable location) cannot redirect a write, and a read through a symlink fails
// loudly instead of silently trusting whatever it points at.
const noFollowFlag = syscall.O_NOFOLLOW
