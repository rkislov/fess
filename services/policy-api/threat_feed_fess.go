package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"fence/pkg/threatfeed"
)

func syncFessFeed(ctx context.Context, db *sql.DB, cfg threatfeed.Config) error {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return fmt.Errorf("fess feed: API-ключ подписки не задан")
	}
	now := time.Now().UTC()
	markThreatFeedAttempt(ctx, db, now)

	ipURL := cfg.ResolvedIPFeedURL()
	body, err := fetchThreatFeedHTTP(ctx, ipURL, cfg, threatFeedRequestTimeout(cfg))
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	rows, err := threatfeed.ParseFeedBody(body, "plain", "", "")
	if err != nil {
		recordThreatFeedFail(ctx, db, err.Error())
		return err
	}
	ips := threatfeed.ValidIPCIDR(threatfeed.UniqueIndicators(rows))

	var hashes []string
	if hashURL := cfg.ResolvedHashFeedURL(); hashURL != "" {
		hbody, herr := fetchThreatFeedHTTP(ctx, hashURL, cfg, threatFeedRequestTimeout(cfg))
		if herr != nil {
			recordThreatFeedFail(ctx, db, herr.Error())
			return herr
		}
		for _, line := range strings.Split(string(hbody), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if h := threatfeed.NormalizeFileHash(line); h != "" {
				hashes = append(hashes, h)
			}
		}
		hashes = threatfeed.UniqueFileHashes(hashes)
	}

	parsed := threatfeed.ThreatFoxParsed{IPs: ips, Hashes: hashes}
	if parsed.Total() == 0 {
		detail := fmt.Sprintf("fess feed: пустой ответ (ips=%d hashes=%d)", len(ips), len(hashes))
		recordThreatFeedFail(ctx, db, detail)
		return fmt.Errorf("%s", detail)
	}
	_, err = replaceThreatFoxData(ctx, db, parsed, now)
	return err
}
