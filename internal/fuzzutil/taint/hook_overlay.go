//go:build taintoverlay

package taint

import "runtime/taintsink"

const overlayActive = true

func init() { taintsink.Hook = hook }
