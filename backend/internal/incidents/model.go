package incidents

import "time"

type Status string

const (
	StatusOpen    Status = "open"
	StatusTriaged Status = "triaged"
	StatusClosed  Status = "closed"
)

type Incident struct {
	ID           int64     `json:"id"`
	RuleID       string    `json:"rule_id"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Severity     string    `json:"severity"`
	HostID       string    `json:"host_id"`
	Status       Status    `json:"status"`
	FirstEventTS time.Time `json:"first_event_ts"`
	LastEventTS  time.Time `json:"last_event_ts"`
	EventIDs     []int64   `json:"event_ids"`
	Tags         []string  `json:"tags"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
