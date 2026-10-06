package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"fence/pkg/auth"
)

func ensureDefaultAdmin(ctx context.Context, db *sql.DB) error {
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := auth.HashPassword("fessfess")
	if err != nil {
		return err
	}
	id := uuid.NewString()
	_, err = db.ExecContext(ctx, `
INSERT INTO users(id, username, display_name, email, password_hash, role, auth_provider, active)
VALUES ($1::uuid, 'admin', 'Administrator', '', $2, 'admin', 'local', TRUE)`, id, hash)
	return err
}

func loadAuthSettings(ctx context.Context, db *sql.DB) (auth.AuthSettings, error) {
	var s auth.AuthSettings
	err := db.QueryRowContext(ctx, `
SELECT local_auth_enabled, ldap_enabled, ldap_url, ldap_bind_dn, ldap_bind_password,
       ldap_base_dn, ldap_user_filter, ldap_user_attr
FROM auth_settings WHERE singleton = 'global'`).Scan(
		&s.LocalAuthEnabled, &s.LDAPEnabled, &s.LDAPURL, &s.LDAPBindDN, &s.LDAPBindPassword,
		&s.LDAPBaseDN, &s.LDAPUserFilter, &s.LDAPUserAttr,
	)
	return s, err
}

func saveAuthSettings(ctx context.Context, db *sql.DB, s auth.AuthSettings) error {
	_, err := db.ExecContext(ctx, `
UPDATE auth_settings SET
  local_auth_enabled = $1,
  ldap_enabled = $2,
  ldap_url = $3,
  ldap_bind_dn = $4,
  ldap_bind_password = CASE WHEN $5 = '' THEN ldap_bind_password ELSE $5 END,
  ldap_base_dn = $6,
  ldap_user_filter = $7,
  ldap_user_attr = $8,
  updated_at = NOW()
WHERE singleton = 'global'`,
		s.LocalAuthEnabled, s.LDAPEnabled, s.LDAPURL, s.LDAPBindDN, strings.TrimSpace(s.LDAPBindPassword),
		s.LDAPBaseDN, s.LDAPUserFilter, s.LDAPUserAttr,
	)
	return err
}

func findUserByUsername(ctx context.Context, db *sql.DB, username string) (auth.User, error) {
	var u auth.User
	var last sql.NullTime
	err := db.QueryRowContext(ctx, `
SELECT id::text, username, display_name, email, role, auth_provider, ldap_dn, active, last_login_at, created_at, updated_at
FROM users WHERE lower(username) = lower($1)`, strings.TrimSpace(username)).Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &u.AuthProvider, &u.LDAPDN, &u.Active,
		&last, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return u, err
	}
	if last.Valid {
		u.LastLoginAt = &last.Time
	}
	return u, nil
}

func findUserByID(ctx context.Context, db *sql.DB, id string) (auth.User, error) {
	var u auth.User
	var last sql.NullTime
	err := db.QueryRowContext(ctx, `
SELECT id::text, username, display_name, email, role, auth_provider, ldap_dn, active, last_login_at, created_at, updated_at
FROM users WHERE id = $1::uuid`, id).Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &u.AuthProvider, &u.LDAPDN, &u.Active,
		&last, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return u, err
	}
	if last.Valid {
		u.LastLoginAt = &last.Time
	}
	return u, nil
}

func getUserPasswordHash(ctx context.Context, db *sql.DB, id string) (string, error) {
	var h string
	err := db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = $1::uuid`, id).Scan(&h)
	return h, err
}

func listUsers(ctx context.Context, db *sql.DB) ([]auth.User, error) {
	rows, err := db.QueryContext(ctx, `
SELECT id::text, username, display_name, email, role, auth_provider, ldap_dn, active, last_login_at, created_at, updated_at
FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.User
	for rows.Next() {
		var u auth.User
		var last sql.NullTime
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &u.AuthProvider, &u.LDAPDN, &u.Active, &last, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		if last.Valid {
			u.LastLoginAt = &last.Time
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func createLocalUser(ctx context.Context, db *sql.DB, username, displayName, email, password, role string) (auth.User, error) {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return auth.User{}, err
	}
	id := uuid.NewString()
	_, err = db.ExecContext(ctx, `
INSERT INTO users(id, username, display_name, email, password_hash, role, auth_provider, active)
VALUES ($1::uuid, $2, $3, $4, $5, $6, 'local', TRUE)`,
		id, strings.TrimSpace(username), strings.TrimSpace(displayName), strings.TrimSpace(email), hash, role,
	)
	if err != nil {
		return auth.User{}, err
	}
	return findUserByID(ctx, db, id)
}

func upsertLDAPUser(ctx context.Context, db *sql.DB, lr auth.LDAPResult, roleDefault string) (auth.User, error) {
	if roleDefault == "" {
		roleDefault = auth.RoleViewer
	}
	existing, err := findUserByUsername(ctx, db, lr.Username)
	if err == nil {
		_, err = db.ExecContext(ctx, `
UPDATE users SET ldap_dn = $2, display_name = CASE WHEN display_name = '' THEN $3 ELSE display_name END,
  email = CASE WHEN email = '' THEN $4 ELSE email END, auth_provider = 'ldap', updated_at = NOW()
WHERE id = $1::uuid`, existing.ID, lr.DN, lr.DisplayName, lr.Email)
		if err != nil {
			return auth.User{}, err
		}
		return findUserByID(ctx, db, existing.ID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, err
	}
	id := uuid.NewString()
	_, err = db.ExecContext(ctx, `
INSERT INTO users(id, username, display_name, email, password_hash, role, auth_provider, ldap_dn, active)
VALUES ($1::uuid, $2, $3, $4, '', $5, 'ldap', $6, TRUE)`,
		id, lr.Username, lr.DisplayName, lr.Email, roleDefault, lr.DN,
	)
	if err != nil {
		return auth.User{}, err
	}
	return findUserByID(ctx, db, id)
}

func updateUserRecord(ctx context.Context, db *sql.DB, id string, displayName, email, role string, active *bool, password string) error {
	if password != "" {
		hash, err := auth.HashPassword(password)
		if err != nil {
			return err
		}
		_, err = db.ExecContext(ctx, `
UPDATE users SET display_name = $2, email = $3, role = $4,
  active = COALESCE($5, active), password_hash = $6, updated_at = NOW()
WHERE id = $1::uuid AND auth_provider = 'local'`, id, displayName, email, role, active, hash)
		return err
	}
	_, err := db.ExecContext(ctx, `
UPDATE users SET display_name = $2, email = $3, role = $4,
  active = COALESCE($5, active), updated_at = NOW()
WHERE id = $1::uuid`, id, displayName, email, role, active)
	return err
}

func touchUserLogin(ctx context.Context, db *sql.DB, userID string) {
	_, _ = db.ExecContext(ctx, `UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1::uuid`, userID)
}

func storeRefreshToken(ctx context.Context, db *sql.DB, userID, hash string, expires time.Time) error {
	id := uuid.NewString()
	_, err := db.ExecContext(ctx, `
INSERT INTO refresh_tokens(id, user_id, token_hash, expires_at)
VALUES ($1::uuid, $2::uuid, $3, $4)`, id, userID, hash, expires)
	return err
}

func revokeRefreshToken(ctx context.Context, db *sql.DB, hash string) {
	_, _ = db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL`, hash)
}

func lookupRefreshToken(ctx context.Context, db *sql.DB, hash string) (userID string, err error) {
	err = db.QueryRowContext(ctx, `
SELECT user_id::text FROM refresh_tokens
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()`, hash).Scan(&userID)
	return userID, err
}

func revokeAllUserRefreshTokens(ctx context.Context, db *sql.DB, userID string) {
	_, _ = db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1::uuid AND revoked_at IS NULL`, userID)
}
