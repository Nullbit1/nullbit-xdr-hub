package events

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"log/slog"

	"sentracore/internal/auth"
	"sentracore/internal/incidents"
)

type IngestHandler struct {
	Store       *Store
	Logger      *slog.Logger
	IngestToken string
	Correlator  *incidents.Correlator
}

func (h *IngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.IngestToken != "" {
		if r.Header.Get("X-Api-Key") != h.IngestToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	var e Event
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if e.Source == "" || e.HostID == "" || e.Kind == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := h.Store.Insert(r.Context(), &e); err != nil {
		h.Logger.Error("insert event", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if h.Correlator != nil {
		if err := h.Correlator.ProcessEvent(r.Context(), &e); err != nil {
			h.Logger.Error("correlate event", "err", err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id": e.ID,
	})
}

type QueryHandler struct {
	Store  *Store
	Logger *slog.Logger
}

func (h *QueryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Authentication is handled by middleware; we just ensure it ran.
	if _, ok := auth.UserFromContext(r.Context()); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	q := r.URL.Query()
	filter := Filter{}
	filter.HostID = q.Get("host_id")
	filter.Source = q.Get("source")
	filter.Kind = q.Get("kind")
	if sev := q.Get("severity"); sev != "" {
		filter.Severity = Severity(sev)
	}
	filter.Tag = q.Get("tag")
	if sinceStr := q.Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			filter.Since = t
		}
	}
	if untilStr := q.Get("until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			filter.Until = t
		}
	}
	if limitStr := q.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = l
		}
	}

	events, err := h.Store.List(r.Context(), filter)
	if err != nil {
		h.Logger.Error("list events", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}
