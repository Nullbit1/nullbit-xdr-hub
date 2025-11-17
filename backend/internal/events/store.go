package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Insert(ctx context.Context, e *Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = SeverityLow
	}
	if e.Tags == nil {
		e.Tags = []string{}
	}
	if e.Fields == nil {
		e.Fields = map[string]interface{}{}
	}
	fieldsJSON, err := json.Marshal(e.Fields)
	if err != nil {
		return err
	}
	const q = `
		INSERT INTO events (source, host_id, ts, kind, severity, tags, fields, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at
	`
	row := s.db.QueryRowContext(ctx, q,
		e.Source,
		e.HostID,
		e.Timestamp,
		e.Kind,
		e.Severity,
		pq.Array(e.Tags),
		string(fieldsJSON),
		time.Now().UTC(),
	)
	return row.Scan(&e.ID, &e.CreatedAt)
}

func (s *Store) List(ctx context.Context, f Filter) ([]Event, error) {
	clauses := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if f.HostID != "" {
		clauses = append(clauses, "host_id = $"+itoa(argIdx))
		args = append(args, f.HostID)
		argIdx++
	}
	if f.Source != "" {
		clauses = append(clauses, "source = $"+itoa(argIdx))
		args = append(args, f.Source)
		argIdx++
	}
	if f.Kind != "" {
		clauses = append(clauses, "kind = $"+itoa(argIdx))
		args = append(args, f.Kind)
		argIdx++
	}
	if f.Severity != "" {
		clauses = append(clauses, "severity = $"+itoa(argIdx))
		args = append(args, string(f.Severity))
		argIdx++
	}
	if !f.Since.IsZero() {
		clauses = append(clauses, "ts >= $"+itoa(argIdx))
		args = append(args, f.Since)
		argIdx++
	}
	if !f.Until.IsZero() {
		clauses = append(clauses, "ts <= $"+itoa(argIdx))
		args = append(args, f.Until)
		argIdx++
	}

	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	query := "SELECT id, source, host_id, ts, kind, severity, tags, fields, created_at FROM events WHERE " +
		strings.Join(clauses, " AND ") + " ORDER BY ts DESC LIMIT " + itoa(limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []Event
	for rows.Next() {
		var e Event
		var tags pq.StringArray
		var fieldsJSON []byte
		if err := rows.Scan(&e.ID, &e.Source, &e.HostID, &e.Timestamp, &e.Kind,
			&e.Severity, &tags, &fieldsJSON, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Tags = []string(tags)
		if len(fieldsJSON) > 0 {
			if err := json.Unmarshal(fieldsJSON, &e.Fields); err != nil {
				return nil, err
			}
		}
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if f.Tag != "" {
		filtered := result[:0]
		for _, e := range result {
			for _, t := range e.Tags {
				if t == f.Tag {
					filtered = append(filtered, e)
					break
				}
			}
		}
		result = filtered
	}
	return result, nil
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
