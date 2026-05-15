// thor-scan is a small HTTP service that runs Nextron THOR Lite on uploaded files.
// multipart: JSON field "meta" (see Fence malware_settings.thor) then file field "upload".
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type scanResponse struct {
	Clean  bool   `json:"clean"`
	Reason string `json:"reason,omitempty"`
}

type fenceMeta struct {
	ContentType   string `json:"content_type"`
	ThorBin       string `json:"thor_bin"`
	ThorDir       string `json:"thor_dir"`
	ExtraArgs     string `json:"extra_args"`
	TimeoutSec    int    `json:"timeout_sec"`
	MaxUploadMB   int    `json:"max_upload_mb"`
	ExitClean     string `json:"exit_clean"`
	ExitThreat    string `json:"exit_threat"`
	LogScanOutput bool   `json:"log_scan_output"`
	LogCommands   bool   `json:"log_commands"`
	LogRequests   bool   `json:"log_requests"`
}

func main() {
	addr := getenv("THOR_SCAN_LISTEN", ":8830")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("POST /scan", handleScan)
	s := &http.Server{Addr: addr, Handler: mux}
	log.Printf("thor-scan listening on %s (default THOR_BIN=%s)", addr, getenv("THOR_BIN", "/opt/thor/thor64"))
	log.Fatal(s.ListenAndServe())
}

func getenv(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}

func parseFenceMeta(raw string) fenceMeta {
	m := fenceMeta{LogRequests: true}
	if strings.TrimSpace(raw) == "" {
		return m
	}
	_ = json.Unmarshal([]byte(raw), &m)
	return m
}

func effectiveBin(m fenceMeta) string {
	if b := strings.TrimSpace(m.ThorBin); b != "" {
		return b
	}
	return getenv("THOR_BIN", "/opt/thor/thor64")
}

func effectiveDir(m fenceMeta) string {
	if d := strings.TrimSpace(m.ThorDir); d != "" {
		return d
	}
	return getenv("THOR_DIR", "/opt/thor")
}

func multipartMaxBytes(m fenceMeta) int64 {
	const capLimit = int64(128 << 20)
	mb := m.MaxUploadMB
	if mb <= 0 {
		if s := strings.TrimSpace(getenv("THOR_SCAN_MAX_BYTES", "")); s != "" {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
				if n > capLimit {
					return capLimit
				}
				return n
			}
		}
		mb = 32
	}
	n := int64(mb) << 20
	if n <= 0 || n > capLimit {
		return capLimit
	}
	return n
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	bin := getenv("THOR_BIN", "/opt/thor/thor64")
	if _, err := os.Stat(bin); err != nil {
		http.Error(w, "THOR binary missing: "+bin, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	meta := parseFenceMeta(r.FormValue("meta"))
	bin := effectiveBin(meta)

	maxBytes := multipartMaxBytes(meta)
	if err := r.ParseMultipartForm(maxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, scanResponse{Clean: false, Reason: "multipart: " + err.Error()})
		return
	}
	f, fh, err := r.FormFile("upload")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, scanResponse{Clean: false, Reason: "missing form file upload: " + err.Error()})
		return
	}
	defer f.Close()

	if meta.LogRequests {
		var n int64
		var fn string
		if fh != nil {
			n = fh.Size
			fn = fh.Filename
		}
		base := filepath.Base(fn)
		if base == "" || base == "." {
			base = "upload"
		}
		log.Printf("thor-scan: scan file=%s size=%d content_type=%q", base, n, meta.ContentType)
	}

	if _, err := os.Stat(bin); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, scanResponse{Clean: false, Reason: "THOR binary missing: " + bin})
		return
	}

	tmpDir, err := os.MkdirTemp("", "thor-scan-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, scanResponse{Clean: false, Reason: "tmpdir: " + err.Error()})
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	base := "upload.bin"
	if fh != nil && fh.Filename != "" {
		base = filepath.Base(fh.Filename)
	}
	dest := filepath.Join(tmpDir, base)
	out, err := os.Create(dest)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, scanResponse{Clean: false, Reason: "create temp: " + err.Error()})
		return
	}
	if _, err := io.Copy(out, f); err != nil {
		_ = out.Close()
		writeJSON(w, http.StatusInternalServerError, scanResponse{Clean: false, Reason: "read body: " + err.Error()})
		return
	}
	_ = out.Close()

	ctx := r.Context()
	toSec := meta.TimeoutSec
	if toSec <= 0 {
		if s := getenv("THOR_SCAN_TIMEOUT_SEC", "120"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				toSec = n
			}
		}
		if toSec <= 0 {
			toSec = 120
		}
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, time.Duration(toSec)*time.Second)
	defer cancel()

	dir := effectiveDir(meta)
	clean, reason, thorOut := runThor(ctx, meta, bin, dir, dest)
	if meta.LogScanOutput && thorOut != "" {
		if !clean {
			if reason != "" {
				reason = reason + "; thor_output: " + truncateDiag(thorOut, 2000)
			} else {
				reason = "thor_output: " + truncateDiag(thorOut, 2000)
			}
		} else {
			log.Printf("thor-scan: stdout (clean, log_scan_output): %s", truncateDiag(thorOut, 2000))
		}
	}
	writeJSON(w, http.StatusOK, scanResponse{Clean: clean, Reason: reason})
}

func runThor(ctx context.Context, m fenceMeta, bin, dir, filePath string) (clean bool, reason string, combined string) {
	args := append(parseExtraArgsFromMeta(m), "-p", filePath)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	if m.LogCommands {
		log.Printf("thor-scan: exec %q %+v dir=%s", bin, args, dir)
	}
	out, err := cmd.CombinedOutput()
	combined = strings.TrimSpace(string(out))
	s := combined
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			return false, "thor: " + err.Error(), combined
		}
	}

	if threatReason := matchThorThreat(s); threatReason != "" {
		return false, threatReason, combined
	}
	if looksLikeThorError(s, exit) {
		return false, truncateDiag("thor error (exit "+strconv.Itoa(exit)+"): "+s, 500), combined
	}

	for _, c := range parseExitListFromMeta(m, getenv("THOR_EXIT_CLEAN", "0"), true) {
		if exit == c {
			return true, "", combined
		}
	}
	for _, c := range parseExitListFromMeta(m, getenv("THOR_EXIT_THREAT", ""), false) {
		if exit == c {
			return false, truncateDiag("thor exit "+strconv.Itoa(exit)+" (threat)", 500), combined
		}
	}
	if exit == 0 {
		return true, "", combined
	}
	return false, truncateDiag("thor exit "+strconv.Itoa(exit)+": "+s, 500), combined
}

func parseExtraArgsFromMeta(m fenceMeta) []string {
	if s := strings.TrimSpace(m.ExtraArgs); s != "" {
		return strings.Fields(s)
	}
	es := getenv("THOR_EXTRA_ARGS", "")
	if es != "" {
		return strings.Fields(es)
	}
	return []string{"--silent"}
}

func parseExitListFromMeta(m fenceMeta, envFallback string, isCleanCSV bool) []int {
	var s string
	if isCleanCSV {
		if strings.TrimSpace(m.ExitClean) != "" {
			s = m.ExitClean
		} else if strings.TrimSpace(envFallback) != "" {
			s = envFallback
		} else {
			s = "0"
		}
	} else {
		s = strings.TrimSpace(m.ExitThreat)
		if s == "" {
			s = envFallback
		}
	}
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

var (
	reAlert = regexp.MustCompile(`(?i)\b(ALERT|MATCH|INFECTED|SUSPICIOUS|THREAT|MALICIOUS)\b`)
)

func matchThorThreat(s string) string {
	if !reAlert.MatchString(s) {
		return ""
	}
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		if reAlert.MatchString(line) {
			line = strings.TrimSpace(line)
			if len(line) > 300 {
				line = line[:300] + "…"
			}
			return line
		}
	}
	return "thor: detection signal in output"
}

func looksLikeThorError(s string, exit int) bool {
	ls := strings.ToLower(s)
	if exit == 0 {
		return strings.Contains(ls, "fatal") || strings.Contains(ls, "cannot open") ||
			strings.Contains(ls, "permission denied") || strings.Contains(ls, "no license")
	}
	return strings.Contains(ls, "license") || strings.Contains(ls, "fatal") || strings.Contains(ls, "panic:")
}

func truncateDiag(s string, max int) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v scanResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
