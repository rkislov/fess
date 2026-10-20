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

const icapWriteChunk = 256 << 10 // 256 KiB per write to the ICAP socket

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

	if err := writeICAPREQMOD(conn, host, port, service, encap, reqBodyOffset); err != nil {
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

// writeICAPREQMOD sends REQMOD with ICAP-level Content-Length (RFC 3507) and streams the encapsulated body.
func writeICAPREQMOD(w io.Writer, host string, port int, service string, encap []byte, reqBodyOffset int) error {
	icapHdr := fmt.Sprintf(
		"REQMOD icap://%s:%d/%s ICAP/1.0\r\n"+
			"Host: %s:%d\r\n"+
			"User-Agent: Fence-WAF/1.0\r\n"+
			"Allow: 204\r\n"+
			"Encapsulated: req-hdr=0, req-body=%d\r\n"+
			"Content-Length: %d\r\n\r\n",
		host, port, service, host, port, reqBodyOffset, len(encap))
	if _, err := io.WriteString(w, icapHdr); err != nil {
		return err
	}
	for off := 0; off < len(encap); off += icapWriteChunk {
		end := off + icapWriteChunk
		if end > len(encap) {
			end = len(encap)
		}
		if _, err := w.Write(encap[off:end]); err != nil {
			return err
		}
	}
	return nil
}

func buildEncapsulatedHTTP(method, requestURI, host, contentType string, body []byte) (encap []byte, reqBodyOffset int) {
	if !strings.HasPrefix(requestURI, "/") && !strings.HasPrefix(requestURI, "http://") && !strings.HasPrefix(requestURI, "https://") {
		requestURI = "/" + requestURI
	}
	// RFC 3507 §4.4: at req-body offset the payload MUST be HTTP chunked (hex size line + data + "0\r\n\r\n").
	// Raw body after headers makes c-icap close the connection (reset by peer on read response).
	hdr := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\n\r\n",
		method, requestURI, host, contentType)
	reqBodyOffset = len(hdr)
	var b strings.Builder
	b.Grow(len(hdr) + len(body) + 32)
	b.WriteString(hdr)
	fmt.Fprintf(&b, "%x\r\n", len(body))
	b.Write(body)
	b.WriteString("\r\n0\r\n\r\n")
	return []byte(b.String()), reqBodyOffset
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
