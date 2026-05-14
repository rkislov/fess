package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	defaultListLimit = 100
	maxListLimit     = 200
)

// parseListPagination reads limit (default 100, max 200, min 1) and offset (default 0, min 0).
func parseListPagination(r *http.Request) (limit int, offset int, err error) {
	limit = defaultListLimit
	offset = 0
	q := r.URL.Query()
	if s := strings.TrimSpace(q.Get("limit")); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 {
			return 0, 0, fmt.Errorf("invalid limit")
		}
		limit = n
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	if s := strings.TrimSpace(q.Get("offset")); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 0 {
			return 0, 0, fmt.Errorf("invalid offset")
		}
		offset = n
	}
	return limit, offset, nil
}
