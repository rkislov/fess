// thor-scan is a small HTTP service that runs Nextron THOR Lite on uploaded files.
// It implements the same contract as pkg/malware httpPostFileScan: POST multipart field "upload", JSON {"clean":bool,"reason":...}.
//
// Mount the official THOR Lite Linux bundle under THOR_DIR (e.g. /opt/thor) and set THOR_BIN (e.g. /opt/thor/thor64).
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

func main() {
	addr := getenv("THOR_SCAN_LISTEN", ":8830")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("POST /scan", handleScan)
	s := &http.Server{Addr: addr, Handler: mux}
	log.Printf("thor-scan listening on %s (THOR_BIN=%s THOR_DIR=%s)", addr, getenv("THOR_BIN", "/opt/thor/thor64"), getenv("THOR_DIR", "/opt/thor"))
	log.Fatal(s.ListenAndServe())
}

func getenv(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
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
	bin := getenv("THOR_BIN", "/opt/thor/thor64")
	if _, err := os.Stat(bin); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, scanResponse{Clean: false, Reason: "THOR binary missing: " + bin})
		return
	}
	maxBytes := int64(32 << 20)
	if s := getenv("THOR_SCAN_MAX_BYTES", ""); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			maxBytes = n
		}
	}
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
	if to := getenv("THOR_SCAN_TIMEOUT_SEC", "120"); to != "" {
		if sec, err := strconv.Atoi(to); err == nil && sec > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(sec)*time.Second)
			defer cancel()
		}
	}

	clean, reason := runThor(ctx, bin, dest)
	writeJSON(w, http.StatusOK, scanResponse{Clean: clean, Reason: reason})
}

func runThor(ctx context.Context, bin, filePath string) (clean bool, reason string) {
	dir := getenv("THOR_DIR", "/opt/thor")
	args := append(parseExtraArgs(), "-p", filePath)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			return false, "thor: " + err.Error()
		}
	}

	if threatReason := matchThorThreat(s); threatReason != "" {
		return false, threatReason
	}
	if looksLikeThorError(s, exit) {
		return false, truncateDiag("thor error (exit " + strconv.Itoa(exit) + "): " + s)
	}

	// Default: exit 0 => clean; known "no detection" exit codes from THOR may vary — allow override.
	for _, c := range parseExitList(getenv("THOR_EXIT_CLEAN", "0")) {
		if exit == c {
			return true, ""
		}
	}
	for _, c := range parseExitList(getenv("THOR_EXIT_THREAT", "")) {
		if exit == c {
			return false, truncateDiag("thor exit " + strconv.Itoa(exit) + " (threat)")
		}
	}
	if exit == 0 {
		return true, ""
	}
	// Unknown non-zero: treat as suspicious (block) with short log.
	return false, truncateDiag("thor exit " + strconv.Itoa(exit) + ": " + s)
}

func parseExtraArgs() []string {
	s := strings.TrimSpace(os.Getenv("THOR_EXTRA_ARGS"))
	if s != "" {
		return strings.Fields(s)
	}
	return []string{"--silent"}
}

func parseExitList(s string) []int {
	if s == "" {
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

func truncateDiag(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v scanResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
