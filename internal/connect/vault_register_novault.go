// vault_register_novault.go — novault-build sibling of vault_register.go
// (ADR-109 step 6). Registers nothing: see vault_register.go's doc comment
// for why this tag exists (completeness/testability) despite vault.go having
// no cloud SDK to drop.
//
//go:build novault

package connect
