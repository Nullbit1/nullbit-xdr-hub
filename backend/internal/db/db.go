package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/lib/pq"
)

func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	return db, nil
}

func RunMigrations(ctx context.Context, db *sql.DB, basePath string) error {
	path := filepath.Join(basePath, "schema.sql")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	if _, err := db.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}
