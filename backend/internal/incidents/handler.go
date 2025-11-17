package incidents

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"log/slog"

	"sentracore/internal/auth"
)

type ListHandler struct {
	Store  *Store
	Logger *slog.Logger
}

func (h *ListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := auth.UserFromContext(r.Context()); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	q := r.URL.Query()
	filter := ListFilter{}
	filter.HostID = q.Get("host_id")
	if status := q.Get("status"); status != "" {
		filter.Status = Status(status)
	}
	filter.Severity = q.Get("severity")
	if limitStr := q.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = l
		}
	}

	incs, err := h.Store.List(r.Context(), filter)
	if err != nil {
		h.Logger.Error("list incidents", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(incs)
}

type DetailHandler struct {
	Store  *Store
	Logger *slog.Logger
}

func (h *DetailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := auth.UserFromContext(r.Context()); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Path is /api/v1/incidents/{id}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	idStr := parts[3]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		inc, err := h.Store.Get(r.Context(), id)
		if err != nil {
			h.Logger.Error("get incident", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inc)
		return
	}

	// PATCH: update status
	user, _ := auth.UserFromContext(r.Context())
	if user.Role == auth.RoleReadOnly {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var payload struct {
		Status Status `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Status == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := h.Store.UpdateStatus(r.Context(), id, payload.Status); err != nil {
		h.Logger.Error("update incident", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
