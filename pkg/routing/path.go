package routing

import "strings"

// NormalizePathPrefix returns a canonical path prefix ("" or "/foo" without trailing slash).
func NormalizePathPrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return ""
	}
	return p
}

// RequestPath returns the path used for backend prefix matching.
func RequestPath(urlPath string) string {
	p := strings.TrimSpace(urlPath)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

// PathMatchesPrefix reports whether reqPath is under prefix (prefix normalized).
func PathMatchesPrefix(reqPath, prefix string) bool {
	prefix = NormalizePathPrefix(prefix)
	if prefix == "" {
		return true
	}
	reqPath = RequestPath(reqPath)
	if reqPath == prefix {
		return true
	}
	return strings.HasPrefix(reqPath, prefix+"/")
}

// StripPathPrefix removes a matched prefix from reqPath for upstream forwarding.
func StripPathPrefix(reqPath, prefix string) string {
	prefix = NormalizePathPrefix(prefix)
	reqPath = RequestPath(reqPath)
	if prefix == "" {
		return reqPath
	}
	if reqPath == prefix {
		return "/"
	}
	if strings.HasPrefix(reqPath, prefix+"/") {
		rest := strings.TrimPrefix(reqPath, prefix)
		if rest == "" {
			return "/"
		}
		return rest
	}
	return reqPath
}
