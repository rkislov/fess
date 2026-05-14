// Package icap implements a minimal ICAP/1.0 REQMOD client (RFC 3507) for antivirus gateways (e.g. c-icap + ClamAV).
package icap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// ScanREQMOD sends encapsulated HTTP request+body to icap://host:port/service and interprets the ICAP response.
func ScanREQMOD(ctx context.Context, host string, port int, service, method, requestURI, httpHost, contentType string, body []byte, timeout time.Duration) (clean bool, detail string, err error) {
	if port <= 0 {
		port = 1344
	}
	if service == "" {
		service = "avscan"
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	encap, reqBodyOffset := buildEncapsulatedHTTP(method, requestURI, httpHost, contentType, body)

	var sb strings.Builder
	fmt.Fprintf(&sb, "REQMOD icap://%s:%d/%s ICAP/1.0\r\n", host, port, service)
	fmt.Fprintf(&sb, "Host: %s:%d\r\n", host, port)
	sb.WriteString("User-Agent: Fence-WAF/1.0\r\n")
	sb.WriteString("Allow: 204\r\n")
	fmt.Fprintf(&sb, "Encapsulated: req-hdr=0, req-body=%d\r\n", reqBodyOffset)
	sb.WriteString("\r\n")
	sb.Write(encap)

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return false, "", err
	}

	br := bufio.NewReader(conn)
	var hdr strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return false, "", fmt.Errorf("icap read headers: %w", err)
		}
		if line == "\r\n" {
			break
		}
		hdr.WriteString(line)
	}

	h := hdr.String()
	firstLine, _, _ := strings.Cut(h, "\r\n")
	fl := strings.ToLower(firstLine)
	if strings.Contains(fl, " 204 ") {
		return true, "ICAP 204", nil
	}

	lower := strings.ToLower(h)
	if strings.Contains(lower, "x-infection-found") ||
		strings.Contains(lower, "x-virus") ||
		strings.Contains(lower, "virus found") {
		return false, strings.TrimSpace(headerValueCI(h, "X-Infection-Found")), nil
	}

	if cl := atoiHeader(h, "Content-Length"); cl > 0 {
		icapBody := make([]byte, cl)
		if _, err := io.ReadFull(br, icapBody); err != nil {
			return false, "", fmt.Errorf("icap read body: %w", err)
		}
		lb := strings.ToLower(string(icapBody))
		if strings.Contains(lb, "virus") ||
			strings.Contains(lb, "infected") ||
			strings.Contains(lb, "malware") {
			return false, "ICAP body threat marker", nil
		}
		if strings.Contains(lb, "http/1.") && (strings.Contains(lb, " 403 ") ||
			strings.Contains(lb, " 451 ") ||
			strings.Contains(lb, "forbidden")) {
			return false, "ICAP encapsulated HTTP 403", nil
		}
	}

	if strings.Contains(fl, " 200 ") {
		return true, "ICAP 200 (no infection headers)", nil
	}

	return false, firstLine, fmt.Errorf("icap: unexpected response")
}

func buildEncapsulatedHTTP(method, requestURI, host, contentType string, body []byte) (encap []byte, reqBodyOffset int) {
	hdr := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
		method, requestURI, host, contentType, len(body))
	b := make([]byte, 0, len(hdr)+len(body))
	b = append(b, hdr...)
	b = append(b, body...)
	return b, len(hdr)
}

func headerValueCI(block, name string) string {
	for _, line := range strings.Split(block, "\r\n") {
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:i]), name) {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

func atoiHeader(block, name string) int {
	v := headerValueCI(block, name)
	n, _ := strconv.Atoi(v)
	return n
}
