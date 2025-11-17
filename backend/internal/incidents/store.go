package incidents

import (
	"context"
	"database/sql"
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

func (s *Store) Create(ctx context.Context, inc *Incident) error {
	if inc.Status == "" {
		inc.Status = StatusOpen
	}
	if inc.Tags == nil {
		inc.Tags = []string{}
	}
	const q = `
		INSERT INTO incidents
		(rule_id, title, description, severity, host_id, status,
		 first_event_ts, last_event_ts, event_ids, tags, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at, updated_at
	`
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, q,
		inc.RuleID,
		inc.Title,
		inc.Description,
		inc.Severity,
		inc.HostID,
		inc.Status,
		inc.FirstEventTS,
		inc.LastEventTS,
		pq.Array(inc.EventIDs),
		pq.Array(inc.Tags),
		now,
		now,
	)
	return row.Scan(&inc.ID, &inc.CreatedAt, &inc.UpdatedAt)
}

func (s *Store) ExistsSimilar(ctx context.Context, ruleID, hostID string, since time.Time) (bool, error) {
	const q = `
		SELECT 1 FROM incidents
		WHERE rule_id = $1 AND host_id = $2 AND last_event_ts >= $3 AND status != 'closed'
		LIMIT 1
	`
	row := s.db.QueryRowContext(ctx, q, ruleID, hostID, since)
	var one int
	if err := row.Scan(&one); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

type ListFilter struct {
	HostID   string
	Status   Status
	Severity string
	Limit    int
}

func (s *Store) List(ctx context.Context, f ListFilter) ([]Incident, error) {
	clauses := []string{"1=1"}
	args := []interface{}{}
	idx := 1
	if f.HostID != "" {
		clauses = append(clauses, "host_id = $"+itoa(idx))
		args = append(args, f.HostID)
		idx++
	}
	if f.Status != "" {
		clauses = append(clauses, "status = $"+itoa(idx))
		args = append(args, string(f.Status))
		idx++
	}
	if f.Severity != "" {
		clauses = append(clauses, "severity = $"+itoa(idx))
		args = append(args, f.Severity)
		idx++
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := "SELECT id, rule_id, title, description, severity, host_id, status," +
		" first_event_ts, last_event_ts, event_ids, tags, created_at, updated_at" +
		" FROM incidents WHERE " + strings.Join(clauses, " AND ") +
		" ORDER BY created_at DESC LIMIT " + itoa(limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var res []Incident
	for rows.Next() {
		var inc Incident
		var ids pq.Int64Array
		var tags pq.StringArray
		if err := rows.Scan(&inc.ID, &inc.RuleID, &inc.Title, &inc.Description,
			&inc.Severity, &inc.HostID, &inc.Status, &inc.FirstEventTS, &inc.LastEventTS,
			&ids, &tags, &inc.CreatedAt, &inc.UpdatedAt); err != nil {
			return nil, err
		}
		inc.EventIDs = []int64(ids)
		inc.Tags = []string(tags)
		res = append(res, inc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Store) Get(ctx context.Context, id int64) (*Incident, error) {
	const q = `
		SELECT id, rule_id, title, description, severity, host_id, status,
		       first_event_ts, last_event_ts, event_ids, tags, created_at, updated_at
		FROM incidents WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, q, id)
	var inc Incident
	var ids pq.Int64Array
	var tags pq.StringArray
	if err := row.Scan(&inc.ID, &inc.RuleID, &inc.Title, &inc.Description,
		&inc.Severity, &inc.HostID, &inc.Status, &inc.FirstEventTS, &inc.LastEventTS,
		&ids, &tags, &inc.CreatedAt, &inc.UpdatedAt); err != nil {
		return nil, err
	}
	inc.EventIDs = []int64(ids)
	inc.Tags = []string(tags)
	return &inc, nil
}

func (s *Store) UpdateStatus(ctx context.Context, id int64, status Status) error {
	const q = `
		UPDATE incidents SET status = $1, updated_at = $2 WHERE id = $3
	`
	_, err := s.db.ExecContext(ctx, q, status, time.Now().UTC(), id)
	return err
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
