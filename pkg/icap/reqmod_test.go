package icap

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func TestWriteICAPREQMODIncludesContentLength(t *testing.T) {
	encap, off := buildEncapsulatedHTTP("PUT", "/x", "example.com", "application/pdf", []byte("abc"))
	var buf bytes.Buffer
	if err := writeICAPREQMOD(&buf, "clamav-icap", 1344, "avscan", encap, off); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	wantCL := "Content-Length: " + strconv.Itoa(len(encap))
	if !strings.Contains(out, wantCL) {
		t.Fatalf("missing %q in:\n%s", wantCL, out)
	}
	if !strings.Contains(out, "Encapsulated: req-hdr=0, req-body=") {
		t.Fatal("missing Encapsulated")
	}
	if !strings.HasSuffix(out, "3\r\nabc\r\n0\r\n\r\n") {
		t.Fatalf("expected RFC3507 chunked encapsulation suffix, got tail %q", out[len(out)-40:])
	}
}

func TestBuildEncapsulatedHTTPReqBodyOffset(t *testing.T) {
	encap, off := buildEncapsulatedHTTP("PUT", "/f.pdf", "cloud.example", "application/pdf", []byte{1, 2})
	if string(encap[off:]) != "2\r\n\x01\x02\r\n0\r\n\r\n" {
		t.Fatalf("req-body section: %q", encap[off:])
	}
}
