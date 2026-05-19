package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"fence/pkg/auth"
)

type createUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

type updateUserRequest struct {
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	Active      *bool  `json:"active"`
	Password    string `json:"password"`
}

func usersCollectionHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || !auth.CanAdmin(claims.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := listUsers(r.Context(), db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var req createUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if strings.TrimSpace(req.Username) == "" || len(req.Password) < 6 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password (min 6) required"})
			return
		}
		role := req.Role
		if role == "" {
			role = auth.RoleViewer
		}
		if !validRole(role) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role"})
			return
		}
		u, err := createLocalUser(r.Context(), db, req.Username, req.DisplayName, req.Email, req.Password, role)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeAuditLog(r.Context(), db, claims.Username, "create", "user", u.ID, nil, map[string]any{"username": u.Username, "role": u.Role})
		writeJSON(w, http.StatusCreated, u)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func userByIDHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || !auth.CanAdmin(claims.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	if id == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		u, err := findUserByID(r.Context(), db, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, u)
	case http.MethodPut:
		var req updateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Role != "" && !validRole(req.Role) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role"})
			return
		}
		existing, err := findUserByID(r.Context(), db, id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		role := existing.Role
		if req.Role != "" {
			role = req.Role
		}
		if err := updateUserRecord(r.Context(), db, id, req.DisplayName, req.Email, role, req.Active, req.Password); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		u, _ := findUserByID(r.Context(), db, id)
		writeAuditLog(r.Context(), db, claims.Username, "update", "user", id, nil, map[string]any{"role": u.Role, "active": u.Active})
		writeJSON(w, http.StatusOK, u)
	case http.MethodDelete:
		active := false
		if err := updateUserRecord(r.Context(), db, id, "", "", "", &active, ""); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		revokeAllUserRefreshTokens(r.Context(), db, id)
		writeAuditLog(r.Context(), db, claims.Username, "delete", "user", id, nil, nil)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deactivated"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func validRole(role string) bool {
	return role == auth.RoleAdmin || role == auth.RoleOperator || role == auth.RoleViewer
}
