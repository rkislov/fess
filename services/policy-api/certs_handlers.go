package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/acme"

	"fence/pkg/acmeissue"
	"fence/pkg/certs"
)

type certificateRow struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Source            string     `json:"source"`
	Domains           []string   `json:"domains"`
	Issuer            string     `json:"issuer"`
	Serial            string     `json:"serial"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	AutoRenew         bool       `json:"auto_renew"`
	Status            string     `json:"status"`
	LastError         string     `json:"last_error,omitempty"`
	LastIssuedAt      *time.Time `json:"last_issued_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	Sites             []certSite `json:"sites"`
}

type certSite struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	HostPattern string `json:"host_pattern"`
}

type acmeSettingsJSON struct {
	DirectoryURL    string `json:"directory_url"`
	Email           string `json:"email"`
	TOSAgreed       bool   `json:"tos_agreed"`
	HasAccountKey   bool   `json:"has_account_key"`
	AccountURI      string `json:"account_uri"`
	RenewBeforeDays int    `json:"renew_before_days"`
	EABKidSet       bool   `json:"eab_kid_set"`
}

func certificatesHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	switch r.Method {
	case http.MethodGet:
		listCertificates(w, r, db)
	case http.MethodPost:
		createCertificate(w, r, db, rdb)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func certificateByIDHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/"), "/")
	if rest == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	parts := strings.Split(rest, "/")
	id := parts[0]
	if _, err := uuid.Parse(id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid certificate id"})
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			getCertificate(w, r, db, id)
		case http.MethodDelete:
			deleteCertificate(w, r, db, rdb, id)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "renew" && r.Method == http.MethodPost {
		renewCertificate(w, r, db, rdb, id)
		return
	}
	if len(parts) == 2 && parts[1] == "assign" && r.Method == http.MethodPost {
		assignCertificate(w, r, db, rdb, id)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func acmeSettingsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	switch r.Method {
	case http.MethodGet:
		s, err := loadACMESettings(r.Context(), db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s)
	case http.MethodPut:
		var body struct {
			DirectoryURL    string `json:"directory_url"`
			Email           string `json:"email"`
			TOSAgreed       *bool  `json:"tos_agreed"`
			RenewBeforeDays int    `json:"renew_before_days"`
			EABKid          string `json:"eab_kid"`
			EABHMACKey      string `json:"eab_hmac_key"`
			ResetAccount    bool   `json:"reset_account"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		tos := false
		if body.TOSAgreed != nil {
			tos = *body.TOSAgreed
		}
		days := body.RenewBeforeDays
		if days <= 0 {
			days = 30
		}
		dir := strings.TrimSpace(body.DirectoryURL)
		if dir == "" {
			dir = acme.LetsEncryptURL
		}
		_, err := db.ExecContext(r.Context(), `
UPDATE acme_settings SET
  directory_url=$1, email=$2, tos_agreed=$3, renew_before_days=$4,
  eab_kid=CASE WHEN $5 = '' THEN eab_kid ELSE $5 END,
  eab_hmac_key=CASE WHEN $6 = '' THEN eab_hmac_key ELSE $6 END,
  account_key_pem=CASE WHEN $7 THEN NULL ELSE account_key_pem END,
  account_uri=CASE WHEN $7 THEN NULL ELSE account_uri END,
  updated_at=NOW()
WHERE id=1`, dir, strings.TrimSpace(body.Email), tos, days, strings.TrimSpace(body.EABKid), strings.TrimSpace(body.EABHMACKey), body.ResetAccount)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s, err := loadACMESettings(r.Context(), db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func loadACMESettings(ctx context.Context, db *sql.DB) (acmeSettingsJSON, error) {
	var s acmeSettingsJSON
	var key, uri, kid sql.NullString
	err := db.QueryRowContext(ctx, `
SELECT directory_url, email, tos_agreed, COALESCE(account_key_pem,''), COALESCE(account_uri,''),
       renew_before_days, COALESCE(eab_kid,'')
FROM acme_settings WHERE id=1`).Scan(&s.DirectoryURL, &s.Email, &s.TOSAgreed, &key, &uri, &s.RenewBeforeDays, &kid)
	if err != nil {
		return s, err
	}
	s.HasAccountKey = strings.TrimSpace(key.String) != ""
	s.AccountURI = uri.String
	s.EABKidSet = strings.TrimSpace(kid.String) != ""
	return s, nil
}

func listCertificates(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	rows, err := db.QueryContext(r.Context(), `
SELECT c.id::text, c.name, c.source, c.domains::text, COALESCE(c.issuer,''), COALESCE(c.serial,''),
       COALESCE(c.fingerprint_sha256,''), c.not_before, c.not_after, c.auto_renew, c.status,
       COALESCE(c.last_error,''), c.last_issued_at, c.created_at, c.updated_at,
       COALESCE((
         SELECT json_agg(json_build_object('id', s.id, 'name', s.name, 'host_pattern', s.host_pattern))
         FROM sites s WHERE s.certificate_id = c.id
       ), '[]'::json)
FROM certificates c
ORDER BY c.created_at DESC`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	items := make([]certificateRow, 0)
	for rows.Next() {
		it, err := scanCertificateRow(rows)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type certScanner interface {
	Scan(dest ...any) error
}

func scanCertificateRow(rows certScanner) (certificateRow, error) {
	var it certificateRow
	var domainsRaw, sitesRaw string
	var nb, na, li sql.NullTime
	err := rows.Scan(&it.ID, &it.Name, &it.Source, &domainsRaw, &it.Issuer, &it.Serial, &it.FingerprintSHA256,
		&nb, &na, &it.AutoRenew, &it.Status, &it.LastError, &li, &it.CreatedAt, &it.UpdatedAt, &sitesRaw)
	if err != nil {
		return it, err
	}
	_ = json.Unmarshal([]byte(domainsRaw), &it.Domains)
	if it.Domains == nil {
		it.Domains = []string{}
	}
	_ = json.Unmarshal([]byte(sitesRaw), &it.Sites)
	if it.Sites == nil {
		it.Sites = []certSite{}
	}
	if nb.Valid {
		t := nb.Time.UTC()
		it.NotBefore = &t
	}
	if na.Valid {
		t := na.Time.UTC()
		it.NotAfter = &t
	}
	if li.Valid {
		t := li.Time.UTC()
		it.LastIssuedAt = &t
	}
	return it, nil
}

func getCertificate(w http.ResponseWriter, r *http.Request, db *sql.DB, id string) {
	row := db.QueryRowContext(r.Context(), `
SELECT c.id::text, c.name, c.source, c.domains::text, COALESCE(c.issuer,''), COALESCE(c.serial,''),
       COALESCE(c.fingerprint_sha256,''), c.not_before, c.not_after, c.auto_renew, c.status,
       COALESCE(c.last_error,''), c.last_issued_at, c.created_at, c.updated_at,
       COALESCE((
         SELECT json_agg(json_build_object('id', s.id, 'name', s.name, 'host_pattern', s.host_pattern))
         FROM sites s WHERE s.certificate_id = c.id
       ), '[]'::json)
FROM certificates c WHERE c.id=$1::uuid`, id)
	it, err := scanCertificateRow(row)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, it)
}

func createCertificate(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client) {
	var payload struct {
		Name       string   `json:"name"`
		Source     string   `json:"source"`
		Domains    []string `json:"domains"`
		CertPEM    string   `json:"cert_pem"`
		KeyPEM     string   `json:"key_pem"`
		AutoRenew  *bool    `json:"auto_renew"`
		SiteIDs    []string `json:"site_ids"`
		ValidDays  int      `json:"valid_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	src := strings.ToLower(strings.TrimSpace(payload.Source))
	if src == "" {
		src = "manual"
	}
	name := strings.TrimSpace(payload.Name)
	auto := true
	if payload.AutoRenew != nil {
		auto = *payload.AutoRenew
	}
	id := uuid.NewString()
	var certPEM, keyPEM string
	var info certs.Info
	var err error
	switch src {
	case "manual":
		info, err = certs.ParsePair(payload.CertPEM, payload.KeyPEM)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		certPEM, keyPEM = strings.TrimSpace(payload.CertPEM), strings.TrimSpace(payload.KeyPEM)
		if name == "" && len(info.DNSNames) > 0 {
			name = info.DNSNames[0]
		}
		auto = false
	case "self_signed":
		certPEM, keyPEM, info, err = certs.GenerateSelfSigned(payload.Domains, payload.ValidDays)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if name == "" {
			name = info.DNSNames[0]
		}
		auto = false
	case "acme":
		if name == "" && len(payload.Domains) > 0 {
			name = payload.Domains[0]
		}
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name or domains required"})
			return
		}
		if _, err := insertCertificate(r.Context(), db, id, name, "acme", payload.Domains, "", "", certs.Info{}, auto, "pending", ""); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := issueACMEInto(r.Context(), db, rdb, id, payload.Domains, auto); err != nil {
			_, _ = db.ExecContext(r.Context(), `UPDATE certificates SET status='error', last_error=$2, updated_at=NOW() WHERE id=$1::uuid`, id, err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]any{"id": id, "error": err.Error()})
			return
		}
		if err := attachSites(r.Context(), db, rdb, id, payload.SiteIDs); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		getCertificate(w, r, db, id)
		return
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "source must be manual, self_signed or acme"})
		return
	}
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	domains := info.DNSNames
	if len(payload.Domains) > 0 {
		domains = certs.NormalizeDomains(payload.Domains)
	}
	if _, err := insertCertificate(r.Context(), db, id, name, src, domains, certPEM, keyPEM, info, auto, "issued", ""); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := attachSites(r.Context(), db, rdb, id, payload.SiteIDs); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeAuditLog(r.Context(), db, "system", "create", "certificate", id, nil, map[string]any{"name": name, "source": src})
	getCertificate(w, r, db, id)
}

func insertCertificate(ctx context.Context, db *sql.DB, id, name, source string, domains []string, certPEM, keyPEM string, info certs.Info, auto bool, status, lastErr string) (sql.Result, error) {
	dom, _ := json.Marshal(certs.NormalizeDomains(domains))
	var nb, na any
	if !info.NotBefore.IsZero() {
		nb = info.NotBefore
	}
	if !info.NotAfter.IsZero() {
		na = info.NotAfter
	}
	issued := any(nil)
	if status == "issued" {
		issued = time.Now().UTC()
	}
	return db.ExecContext(ctx, `
INSERT INTO certificates(id, name, source, domains, cert_pem, key_pem, issuer, serial, fingerprint_sha256,
  not_before, not_after, auto_renew, status, last_error, last_issued_at)
VALUES ($1::uuid,$2,$3,$4::jsonb,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),$10,$11,$12,$13,NULLIF($14,''),$15)`,
		id, name, source, string(dom), certPEM, keyPEM, info.Issuer, info.Serial, info.FingerprintSHA256,
		nb, na, auto, status, lastErr, issued)
}

func deleteCertificate(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, id string) {
	res, err := db.ExecContext(r.Context(), `DELETE FROM certificates WHERE id=$1::uuid`, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
		return
	}
	_ = publishRoutingUpdate(r.Context(), rdb)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func assignCertificate(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, id string) {
	var payload struct {
		SiteIDs    []string `json:"site_ids"`
		TLSEnabled *bool    `json:"tls_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := attachSites(r.Context(), db, rdb, id, payload.SiteIDs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if payload.TLSEnabled != nil {
		_, err := db.ExecContext(r.Context(), `
UPDATE sites SET tls_enabled=$2, updated_at=NOW() WHERE certificate_id=$1::uuid`, id, *payload.TLSEnabled)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_ = publishRoutingUpdate(r.Context(), rdb)
	}
	getCertificate(w, r, db, id)
}

func attachSites(ctx context.Context, db *sql.DB, rdb *redis.Client, certID string, siteIDs []string) error {
	if siteIDs == nil {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE sites SET certificate_id=NULL, updated_at=NOW() WHERE certificate_id=$1::uuid`, certID); err != nil {
		return err
	}
	for _, sid := range siteIDs {
		sid = strings.TrimSpace(sid)
		if sid == "" {
			continue
		}
		if _, err := uuid.Parse(sid); err != nil {
			return fmt.Errorf("invalid site id")
		}
		res, err := tx.ExecContext(ctx, `
UPDATE sites SET certificate_id=$2::uuid, tls_enabled=TRUE,
  tls_cert_pem=(SELECT cert_pem FROM certificates WHERE id=$2::uuid),
  tls_key_pem=(SELECT key_pem FROM certificates WHERE id=$2::uuid),
  updated_at=NOW()
WHERE id=$1::uuid`, sid, certID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("site not found: %s", sid)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return publishRoutingUpdate(ctx, rdb)
}

func renewCertificate(w http.ResponseWriter, r *http.Request, db *sql.DB, rdb *redis.Client, id string) {
	var source string
	var domainsRaw string
	var auto bool
	err := db.QueryRowContext(r.Context(), `SELECT source, domains::text, auto_renew FROM certificates WHERE id=$1::uuid`, id).Scan(&source, &domainsRaw, &auto)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if source != "acme" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "renew is only for ACME certificates"})
		return
	}
	var domains []string
	_ = json.Unmarshal([]byte(domainsRaw), &domains)
	if err := issueACMEInto(r.Context(), db, rdb, id, domains, auto); err != nil {
		_, _ = db.ExecContext(r.Context(), `UPDATE certificates SET status='error', last_error=$2, updated_at=NOW() WHERE id=$1::uuid`, id, err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	getCertificate(w, r, db, id)
}

func issueACMEInto(ctx context.Context, db *sql.DB, rdb *redis.Client, certID string, domains []string, auto bool) error {
	_ = auto
	dir, email, tos, keyPEM, acctURI, err := loadACMEAccount(ctx, db)
	if err != nil {
		return err
	}
	if !tos {
		return fmt.Errorf("подтвердите согласие с условиями ACME в разделе УЦ")
	}
	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("укажите email для ACME-аккаунта")
	}
	var accountKey *ecdsa.PrivateKey
	if strings.TrimSpace(keyPEM) == "" {
		accountKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		enc, err := certs.EncodeAccountKey(accountKey)
		if err != nil {
			return err
		}
		keyPEM = enc
	} else {
		accountKey, err = certs.ParseAccountKey(keyPEM)
		if err != nil {
			return err
		}
	}
	cli := acmeissue.NewClient(accountKey, dir)
	acct := &acme.Account{Contact: []string{"mailto:" + email}}
	if strings.TrimSpace(acctURI) != "" {
		acct, err = cli.GetReg(ctx, acctURI)
		if err != nil {
			acct, err = cli.Register(ctx, &acme.Account{Contact: []string{"mailto:" + email}}, acme.AcceptTOS)
		}
	} else {
		acct, err = cli.Register(ctx, acct, acme.AcceptTOS)
	}
	if err != nil {
		return fmt.Errorf("ACME account: %w", err)
	}
	_, _ = db.ExecContext(ctx, `UPDATE acme_settings SET account_key_pem=$1, account_uri=$2, updated_at=NOW() WHERE id=1`, keyPEM, acct.URI)
	res, err := acmeissue.IssueHTTP01(ctx, cli, domains, func(ctx context.Context, token, keyAuth string, ttl time.Duration) error {
		_, err := db.ExecContext(ctx, `
INSERT INTO acme_http01_challenges(token, key_authorization, certificate_id, expires_at)
VALUES ($1,$2,$3::uuid, NOW() + ($4 * INTERVAL '1 second'))
ON CONFLICT (token) DO UPDATE SET key_authorization=EXCLUDED.key_authorization, certificate_id=EXCLUDED.certificate_id, expires_at=EXCLUDED.expires_at`,
			token, keyAuth, certID, int(ttl.Seconds()))
		return err
	})
	if err != nil {
		return err
	}
	dom, _ := json.Marshal(res.Info.DNSNames)
	_, err = db.ExecContext(ctx, `
UPDATE certificates SET
  cert_pem=$2, key_pem=$3, domains=$4::jsonb, issuer=$5, serial=$6, fingerprint_sha256=$7,
  not_before=$8, not_after=$9, status='issued', last_error=NULL, last_issued_at=NOW(), updated_at=NOW()
WHERE id=$1::uuid`,
		certID, res.CertPEM, res.KeyPEM, string(dom), res.Info.Issuer, res.Info.Serial, res.Info.FingerprintSHA256,
		res.Info.NotBefore, res.Info.NotAfter)
	if err != nil {
		return err
	}
	_, _ = db.ExecContext(ctx, `
UPDATE sites SET tls_cert_pem=$2, tls_key_pem=$3, tls_enabled=TRUE, updated_at=NOW()
WHERE certificate_id=$1::uuid`, certID, res.CertPEM, res.KeyPEM)
	return publishRoutingUpdate(ctx, rdb)
}

func loadACMEAccount(ctx context.Context, db *sql.DB) (dir, email string, tos bool, keyPEM, acctURI string, err error) {
	err = db.QueryRowContext(ctx, `
SELECT directory_url, email, tos_agreed, COALESCE(account_key_pem,''), COALESCE(account_uri,'')
FROM acme_settings WHERE id=1`).Scan(&dir, &email, &tos, &keyPEM, &acctURI)
	return
}

func runACMERenewPoller(ctx context.Context, db *sql.DB, rdb *redis.Client) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			renewExpiringACME(ctx, db, rdb)
		}
	}
}

func renewExpiringACME(ctx context.Context, db *sql.DB, rdb *redis.Client) {
	var days int
	if err := db.QueryRowContext(ctx, `SELECT renew_before_days FROM acme_settings WHERE id=1`).Scan(&days); err != nil {
		return
	}
	if days <= 0 {
		days = 30
	}
	rows, err := db.QueryContext(ctx, `
SELECT id::text, domains::text FROM certificates
WHERE source='acme' AND auto_renew=TRUE AND status IN ('issued','error')
  AND not_after IS NOT NULL AND not_after < NOW() + ($1 || ' days')::interval`, fmt.Sprintf("%d", days))
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			continue
		}
		var domains []string
		_ = json.Unmarshal([]byte(raw), &domains)
		_ = issueACMEInto(ctx, db, rdb, id, domains, true)
	}
}
