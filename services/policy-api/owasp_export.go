package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"fence/pkg/owasp"
)

func owaspPackExportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("pack_id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pack_id query parameter is required"})
		return
	}
	pack, err := owasp.LoadPack(id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	raw, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	fn := fmt.Sprintf("fence-owasp-%s.json", pack.PackID)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fn))
	_, _ = w.Write(raw)
}
