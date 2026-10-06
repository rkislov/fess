package main

import (
	"net/http"
	"strconv"

	fessdocs "fence/docs"
)

func openAPISpecHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.Itoa(len(fessdocs.OpenAPIYAML)))
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(fessdocs.OpenAPIYAML)
}
