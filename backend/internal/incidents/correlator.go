package incidents

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"sentracore/internal/events"
)

type Correlator struct {
	Rules   []RuleConfig
	Store   *Store
	Events  *events.Store
	Logger  *slog.Logger
}

func NewCorrelator(rules []RuleConfig, store *Store, eventsStore *events.Store, logger *slog.Logger) *Correlator {
	return &Correlator{
		Rules:  rules,
		Store:  store,
		Events: eventsStore,
		Logger: logger,
	}
}

// ProcessEvent runs correlation for a newly ingested event.
func (c *Correlator) ProcessEvent(ctx context.Context, e *events.Event) error {
	for _, rule := range c.Rules {
		// Quick pre-filter: event must match at least one step by source/kind.
		if !eventCouldMatchRule(e, rule) {
			continue
		}
		windowStart := e.Timestamp.Add(-rule.Window)
		// Check if similar open incident already exists.
		exists, err := c.Store.ExistsSimilar(ctx, rule.ID, e.HostID, windowStart)
		if err != nil {
			c.Logger.Error("check existing incident", "err", err, "rule", rule.ID)
			continue
		}
		if exists {
			continue
		}
		// For each step, fetch events in the window and see if at least one matches.
		matchingEvents := make(map[string][]events.Event)
		for _, step := range rule.Steps {
			f := events.Filter{
				HostID: e.HostID,
				Since:  windowStart,
				Until:  e.Timestamp,
				Limit:  500,
			}
			evts, err := c.Events.List(ctx, f)
			if err != nil {
				c.Logger.Error("list events for correlation", "err", err, "rule", rule.ID)
				continue
			}
			for _, ev := range evts {
				if eventMatchesStep(&ev, step.Match) {
					matchingEvents[step.Name] = append(matchingEvents[step.Name], ev)
				}
			}
			if len(matchingEvents[step.Name]) == 0 {
				// This rule is not satisfied for this event.
				matchingEvents = nil
				break
			}
		}
		if matchingEvents == nil {
			continue
		}
		// Build incident from the union of all matched events.
		var ids []int64
		var first, last time.Time
		first = e.Timestamp
		last = e.Timestamp
		for _, evts := range matchingEvents {
			for _, ev := range evts {
				ids = append(ids, ev.ID)
				if ev.Timestamp.Before(first) {
					first = ev.Timestamp
				}
				if ev.Timestamp.After(last) {
					last = ev.Timestamp
				}
			}
		}
		inc := &Incident{
			RuleID:       rule.ID,
			Title:        rule.Title,
			Description:  rule.Description,
			Severity:     rule.Severity,
			HostID:       e.HostID,
			Status:       StatusOpen,
			FirstEventTS: first,
			LastEventTS:  last,
			EventIDs:     ids,
			Tags:         rule.Tags,
		}
		if err := c.Store.Create(ctx, inc); err != nil {
			c.Logger.Error("create incident", "err", err, "rule", rule.ID)
		} else {
			c.Logger.Info("incident created", "id", inc.ID, "rule", rule.ID, "host", inc.HostID)
		}
	}
	return nil
}

func eventCouldMatchRule(e *events.Event, rule RuleConfig) bool {
	for _, step := range rule.Steps {
		if step.Match.Source != "" && step.Match.Source != e.Source {
			continue
		}
		if step.Match.Kind != "" && step.Match.Kind != e.Kind {
			continue
		}
		return true
	}
	return false
}

func eventMatchesStep(e *events.Event, m StepMatch) bool {
	if m.Source != "" && e.Source != m.Source {
		return false
	}
	if m.Kind != "" && e.Kind != m.Kind {
		return false
	}
	if len(m.TagsAny) > 0 {
		found := false
		for _, t := range e.Tags {
			for _, want := range m.TagsAny {
				if t == want {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(m.FieldEquals) > 0 {
		for k, v := range m.FieldEquals {
			val, ok := e.Fields[k]
			if !ok || val == nil {
				return false
			}
			str, ok := val.(string)
			if !ok || str != v {
				return false
			}
		}
	}
	if len(m.FieldContains) > 0 {
		for k, v := range m.FieldContains {
			raw, ok := e.Fields[k]
			if !ok || raw == nil {
				return false
			}
			str, ok := raw.(string)
			if !ok {
				return false
			}
			if !strings.Contains(str, v) {
				return false
			}
		}
	}
	return true
}
