package events

import "time"

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Event struct {
	ID        int64                  `json:"id"`
	Source    string                 `json:"source"`
	HostID    string                 `json:"host_id"`
	Timestamp time.Time              `json:"timestamp"`
	Kind      string                 `json:"kind"`
	Severity  Severity               `json:"severity"`
	Tags      []string               `json:"tags"`
	Fields    map[string]interface{} `json:"fields"`
	CreatedAt time.Time              `json:"created_at"`
}

type Filter struct {
	HostID   string
	Source   string
	Kind     string
	Severity Severity
	Tag      string
	Since    time.Time
	Until    time.Time
	Limit    int
}
