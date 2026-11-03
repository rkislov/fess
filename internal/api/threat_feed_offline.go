package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fence/pkg/threatfeed"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var feedBundleMu sync.Mutex

// A transaction replaces every IOC category together; failed validation never
// clears the last successful snapshot. Web IOCs are stored for correlation.
func replaceOfflineData(ctx context.Context, db *sql.DB, b threatfeed.OfflineBundle, now time.Time) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, table := range []string{"threat_feed_indicators", "threat_feed_file_hashes", "threat_feed_web_iocs"} {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return 0, err
		}
	}
	insert := func(query string, rows [][]any) error {
		st, e := tx.PrepareContext(ctx, query)
		if e != nil {
			return e
		}
		defer st.Close()
		for _, row := range rows {
			if _, e = st.ExecContext(ctx, row...); e != nil {
				return e
			}
		}
		return nil
	}
	rows := make([][]any, 0, len(b.IPs))
	for _, v := range b.IPs {
		rows = append(rows, []any{v})
	}
	if err = insert("INSERT INTO threat_feed_indicators(indicator) VALUES($1)", rows); err != nil {
		return 0, err
	}
	rows = nil
	for _, v := range b.Hashes {
		rows = append(rows, []any{v, hashAlgForHex(v)})
	}
	if err = insert("INSERT INTO threat_feed_file_hashes(hash,hash_alg) VALUES($1,$2)", rows); err != nil {
		return 0, err
	}
	rows = nil
	for typ, values := range map[string][]string{"domain": b.Domains, "url": b.URLs} {
		seen := map[string]bool{}
		for _, v := range values {
			if seen[v] {
				continue
			}
			seen[v] = true
			id := fmt.Sprintf("%x", sha256.Sum256([]byte(typ+":"+v)))
			rows = append(rows, []any{id, typ, v})
		}
	}
	if err = insert("INSERT INTO threat_feed_web_iocs(id,indicator_type,value) VALUES($1,$2,$3)", rows); err != nil {
		return 0, err
	}
	if b.HasBotLists {
		for _, table := range []string{"bot_protection_asn", "bot_protection_cidr"} {
			if _, err = tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
				return 0, err
			}
		}
		asns := map[uint]bool{}
		botRows := [][]any{}
		for _, asn := range b.ASNs {
			if !asns[asn] {
				botRows = append(botRows, []any{asn})
				asns[asn] = true
			}
		}
		if err = insert("INSERT INTO bot_protection_asn(asn) VALUES($1)", botRows); err != nil {
			return 0, err
		}
		seen := map[string]bool{}
		botRows = nil
		for _, cidr := range b.BotCIDRs {
			if !seen[cidr] {
				botRows = append(botRows, []any{cidr})
				seen[cidr] = true
			}
		}
		if err = insert("INSERT INTO bot_protection_cidr(cidr) VALUES($1)", botRows); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE bot_protection_sync_state SET last_attempt_at=$1,last_success_at=$1,last_error='',asn_rows=$2,cidr_rows=$3 WHERE singleton='global'`, now, len(asns), len(seen)); err != nil {
			return 0, err
		}
	}
	// Stage all CVDs before replacing any file; keep old files for rollback until
	// the IOC transaction commits. No paths from ZIP entries are used directly.
	finish, err := stageOfflineClamAV(b.ClamAV)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() { finish(committed) }()
	n := len(b.IPs) + len(b.Hashes) + len(rows)
	if err = finishThreatFeedSyncTx(ctx, tx, n, now); err != nil {
		return 0, err
	}
	committed = true
	return n, nil
}

func stageOfflineClamAV(files map[string]*zip.File) (func(bool), error) {
	noop := func(bool) {}
	if len(files) == 0 {
		return noop, nil
	}
	dir := os.Getenv("FESS_CLAMAV_DATABASE_DIR")
	if dir == "" {
		dir = "/var/lib/fess-clamav"
	}
	stage, err := os.MkdirTemp(dir, ".feed-update-")
	if err != nil {
		return noop, fmt.Errorf("нет прав на обновление баз ClamAV в %s", dir)
	}
	moved := []string{}
	backups := map[string]bool{}
	rollback := func(commit bool) {
		for _, name := range moved {
			dest := filepath.Join(dir, name)
			if !commit {
				os.Remove(dest)
				if backups[name] {
					os.Rename(filepath.Join(stage, name+".old"), dest)
				}
			}
		}
		os.RemoveAll(stage)
		if commit {
			c, e := net.DialTimeout("unix", "/run/fess-clamav/clamd.sock", time.Second)
			if e == nil {
				c.SetDeadline(time.Now().Add(time.Second))
				io.WriteString(c, "zRELOAD\x00")
				c.Close()
			}
		}
	}
	fail := func(e error) (func(bool), error) { rollback(false); return noop, e }
	for _, name := range []string{"main.cvd", "daily.cvd", "bytecode.cvd"} {
		entry := files[name]
		if entry == nil {
			return fail(fmt.Errorf("неполный набор ClamAV"))
		}
		rc, e := entry.Open()
		if e != nil {
			return fail(e)
		}
		header := make([]byte, 512)
		_, e = io.ReadFull(rc, header)
		if e != nil || !bytes.HasPrefix(header, []byte("ClamAV-VDB:")) {
			rc.Close()
			return fail(fmt.Errorf("некорректный заголовок ClamAV"))
		}
		out, e := os.OpenFile(filepath.Join(stage, name), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
		if e != nil {
			rc.Close()
			return fail(e)
		}
		_, e = io.Copy(out, io.MultiReader(bytes.NewReader(header), rc))
		rc.Close()
		ce := out.Close()
		if e != nil {
			return fail(e)
		}
		if ce != nil {
			return fail(ce)
		}
	}
	// CVD and CLD variants must not coexist: clamd would load duplicate bases.
	for _, name := range []string{"main.cld", "daily.cld", "bytecode.cld"} {
		dest := filepath.Join(dir, name)
		if _, e := os.Stat(dest); e == nil {
			if e = os.Rename(dest, filepath.Join(stage, name+".old")); e != nil {
				return fail(e)
			}
			backups[name] = true
			moved = append(moved, name)
		}
	}
	for _, name := range []string{"main.cvd", "daily.cvd", "bytecode.cvd"} {
		dest := filepath.Join(dir, name)
		if _, e := os.Stat(dest); e == nil {
			if e = os.Rename(dest, filepath.Join(stage, name+".old")); e != nil {
				return fail(e)
			}
			backups[name] = true
		}
		if e := os.Rename(filepath.Join(stage, name), dest); e != nil {
			if backups[name] {
				os.Rename(filepath.Join(stage, name+".old"), dest)
			}
			return fail(e)
		}
		moved = append(moved, name)
	}
	return rollback, nil
}

func syncFessBundle(ctx context.Context, db *sql.DB, cfg threatfeed.Config) error {
	feedBundleMu.Lock()
	defer feedBundleMu.Unlock()
	if strings.TrimSpace(cfg.APIKey) == "" {
		return fmt.Errorf("FESS Feed: нужен API-ключ подписки")
	}
	markThreatFeedAttempt(ctx, db, time.Now().UTC())
	// Every enabled upstream is already merged by Feed; do not filter by the
	// old single-provider source selector or fetch inconsistent per-type snapshots.
	body, err := fetchThreatFeedHTTP(ctx, cfg.ResolvedFessFeedBase()+"/feeds/v1/offline.zip", cfg, threatFeedRequestTimeout(cfg))
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	b, err := threatfeed.ParseOffline(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	_, err = replaceOfflineData(ctx, db, b, time.Now().UTC())
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
	}
	return err
}
