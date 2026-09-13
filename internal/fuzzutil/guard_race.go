//go:build race

package fuzzutil

// guardTimeoutScale multiplies GuardTimeout when built with the race detector.
// -race instruments every memory access and slows execution ~10-20x, so a normal
// input can exceed the native 3s budget purely from detector overhead. Scaling the
// budget up avoids that false "hang" while still catching a genuine hang (which
// exceeds even the scaled budget); the rig's MemoryMax still bounds runaway
// allocation regardless.
const guardTimeoutScale = 20
