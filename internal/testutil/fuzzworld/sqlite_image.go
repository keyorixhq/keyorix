package fuzzworld

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"gorm.io/gorm"
)

// sqliteImageLoader is implemented by modernc.org/sqlite's connection
// (conn.Deserialize); the type itself is unexported, hence the interface.
type sqliteImageLoader interface {
	Deserialize(buf []byte) error
}

// OpenSQLiteFromImage returns a gorm handle on a private in-memory SQLite
// database whose content is image: the bytes of a complete SQLite database
// file (for example a seeded template read back from disk). Nothing is written
// to disk, which is the point: harnesses that clone a template per case write
// the whole template for every case when they copy a file.
//
// The database lives and dies with its single pooled connection, so the pool
// is pinned to one connection that is never recycled; close the handle
// (db.DB().Close()) to release the memory. image is copied, not retained.
//
// OpenSQLite is unchanged and remains the choice for file-backed databases.
func OpenSQLiteFromImage(tb testing.TB, image []byte) *gorm.DB {
	tb.Helper()
	db := OpenSQLite(tb, ":memory:", 1)
	sqlDB, err := db.DB()
	if err != nil {
		tb.Fatalf("sqlite image: %v", err)
	}
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)
	sqlDB.SetConnMaxIdleTime(0)
	if err := loadSQLiteImage(sqlDB, image); err != nil {
		_ = sqlDB.Close()
		tb.Fatalf("sqlite image: %v", err)
	}
	return db
}

func loadSQLiteImage(sqlDB *sql.DB, image []byte) error {
	ctx := context.Background()
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // returns the connection to the pool; it stays open
	return conn.Raw(func(dc any) error {
		l, ok := dc.(sqliteImageLoader)
		if !ok {
			return fmt.Errorf("driver connection %T cannot deserialize an image", dc)
		}
		return l.Deserialize(image)
	})
}
