// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerSecretNodesRawSQLAllow("internal/storage/store/secret_node_cache_epoch_integrity.go:bumpAllSecretNodeCacheEpochsTx", secretNodesRawSQLAllowEntry{
		reason: "Not a row reader: after the cache-epoch trigger was found tampered with, it moves cache_epoch of every secret_nodes row so every replica's node cache re-reads (TRIGGER-HARDEN-1). A soft-deleted secret that is restored later must not be served from an entry cached before the tamper, so it must reach soft-deleted rows, which the predicate deleted_at IS NULL would hide.",
	})
}
