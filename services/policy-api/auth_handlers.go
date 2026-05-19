package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"fence/pkg/auth"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func authLoginHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, svc *auth.Service) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}

	settings, err := loadAuthSettings(r.Context(), db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var user auth.User
	loginOK := false

	if settings.LocalAuthEnabled {
		u, err := findUserByUsername(r.Context(), db, req.Username)
		if err == nil && u.AuthProvider == auth.ProviderLocal && u.Active {
			hash, _ := getUserPasswordHash(r.Context(), db, u.ID)
			if auth.CheckPassword(hash, req.Password) {
				user = u
				loginOK = true
			}
		}
	}

	if !loginOK && settings.LDAPEnabled {
		lr, err := auth.AuthenticateLDAP(settings, req.Username, req.Password)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		user, err = upsertLDAPUser(r.Context(), db, lr, auth.RoleViewer)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if !user.Active {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "user disabled"})
			return
		}
		loginOK = true
	}

	if !loginOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	pair, err := issueTokenPair(r, db, svc, user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	touchUserLogin(r.Context(), db, user.ID)
	writeJSON(w, http.StatusOK, map[string]any{"tokens": pair, "user": publicUser(user)})
}

func authRefreshHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, svc *auth.Service) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	hash := auth.HashRefreshToken(req.RefreshToken)
	userID, err := lookupRefreshToken(r.Context(), db, hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid refresh token"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	user, err := findUserByID(r.Context(), db, userID)
	if err != nil || !user.Active {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid refresh token"})
		return
	}
	revokeRefreshToken(r.Context(), db, hash)
	pair, err := issueTokenPair(r, db, svc, user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": pair, "user": publicUser(user)})
}

func authLogoutHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req refreshRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.RefreshToken != "" {
		revokeRefreshToken(r.Context(), db, auth.HashRefreshToken(req.RefreshToken))
	}
	claims, ok := auth.ClaimsFromContext(r.Context())
	if ok && claims.UserID != "" {
		revokeAllUserRefreshTokens(r.Context(), db, claims.UserID)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func authMeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	user, err := findUserByID(r.Context(), db, claims.UserID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(user)})
}

func issueTokenPair(r *http.Request, db *sql.DB, svc *auth.Service, user auth.User) (auth.TokenPair, error) {
	access, exp, err := svc.IssueAccessToken(user)
	if err != nil {
		return auth.TokenPair{}, err
	}
	raw, hash, err := auth.NewRefreshToken()
	if err != nil {
		return auth.TokenPair{}, err
	}
	if err := storeRefreshToken(r.Context(), db, user.ID, hash, time.Now().UTC().Add(svc.RefreshTTL())); err != nil {
		return auth.TokenPair{}, err
	}
	return auth.TokenPair{
		AccessToken:  access,
		RefreshToken: raw,
		ExpiresIn:    int64(time.Until(exp).Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func publicUser(u auth.User) auth.User {
	u = u
	return u
}

func authSettingsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || !auth.CanAdmin(claims.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		s, err := loadAuthSettings(r.Context(), db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.LDAPBindPassword = ""
		writeJSON(w, http.StatusOK, s)
	case http.MethodPut:
		var incoming auth.AuthSettings
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := saveAuthSettings(r.Context(), db, incoming); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeAuditLog(r.Context(), db, claims.Username, "update", "auth_settings", "global", nil, map[string]any{"ldap_enabled": incoming.LDAPEnabled})
		incoming.LDAPBindPassword = ""
		writeJSON(w, http.StatusOK, incoming)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
