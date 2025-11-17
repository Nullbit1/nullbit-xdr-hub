package httpserver

import (
	"encoding/json"
	"net/http"

	"log/slog"

	"sentracore/internal/auth"
	"sentracore/internal/events"
	"sentracore/internal/incidents"
)

func NewRouter(
	logger *slog.Logger,
	authSvc *auth.Service,
	eventStore *events.Store,
	incidentStore *incidents.Store,
	corr *incidents.Correlator,
	ingestToken string,
) http.Handler {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Auth
	mux.Handle("/api/v1/auth/login", loginHandler(authSvc, logger))

	// Events
	ingestHandler := &events.IngestHandler{
		Store:       eventStore,
		Logger:      logger,
		IngestToken: ingestToken,
		Correlator:  corr,
	}
	mux.Handle("/api/v1/ingest/events", ingestHandler)

	queryHandler := &events.QueryHandler{
		Store:  eventStore,
		Logger: logger,
	}

	secured := auth.JWTMiddleware(authSvc)
	mux.Handle("/api/v1/events", secured(queryHandler))

	// Incidents
	listHandler := &incidents.ListHandler{
		Store:  incidentStore,
		Logger: logger,
	}
	detailHandler := &incidents.DetailHandler{
		Store:  incidentStore,
		Logger: logger,
	}
	mux.Handle("/api/v1/incidents", secured(listHandler))
	mux.Handle("/api/v1/incidents/", secured(detailHandler))

	// CORS wrapper (simple, for local UI/tools).
	return withCORS(mux)
}
