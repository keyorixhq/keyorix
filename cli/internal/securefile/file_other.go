//go:build !unix

package securefile

// noFollowFlag is a no-op outside unix-like systems, which lack a portable
// O_NOFOLLOW-equivalent open flag in the standard library.
const noFollowFlag = 0
