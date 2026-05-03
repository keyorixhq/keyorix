// local_sharing.go — ShareRecord operations for LocalStorage.
//
// Status: NOT YET IMPLEMENTED.
// The sharing domain exists but direct-DB sharing queries have not been written.
// Remote sharing is fully implemented in remote_sharing.go.
//
// When implementing, use the same patterns as local_secrets.go:
//   - GORM queries on models.ShareRecord
//   - i18n error messages
//   - Check row count for not-found errors on Delete
package store

// No functions yet — placeholder file to make the operation map in entry.go accurate.
// Add LocalStorage methods here as sharing queries are implemented.
