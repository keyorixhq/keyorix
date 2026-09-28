// kubernetes_nok8s.go — nok8s-build sibling of kubernetes.go (ADR-109 step 6).
// Registers nothing: the kubernetes dynamic-secret backend is not available in a
// build tagged nok8s, and New("kubernetes") falls through to cloudEngines' "not
// available in this build" error. See kubernetes.go's doc comment for why AIR-GAPPED
// itself does not set this tag.
//
//go:build nok8s

package dynamic
