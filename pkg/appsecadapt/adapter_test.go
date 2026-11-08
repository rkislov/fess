package appsecadapt

import (
	"net/http/httptest"
	"strings"
	"testing"
)

const example = `name: crowdsecurity/test
rules:
 - and:
   - zones: [METHOD]
     match: {type: equals, value: GET}
   - zones: [URI]
     transform: [lowercase]
     match: {type: equals, value: /probe}
labels: {service: http}
`

func TestBooleanAndDecodedPath(t *testing.T) {
	r := Adapt([]byte(example))
	if !r.Supported {
		t.Fatal(r.Reasons)
	}
	c, e := Compile(*r.Expression)
	if e != nil {
		t.Fatal(e)
	}
	for _, x := range []struct {
		method, path string
		want         bool
	}{{"GET", "/Pr%6fbe", true}, {"POST", "/probe", false}, {"GET", "/other", false}} {
		if got := c.Matches(httptest.NewRequest(x.method, x.path, nil), nil); got != x.want {
			t.Fatal(x, got)
		}
	}
}
func TestUnsupportedNeverDropsAndChild(t *testing.T) {
	for _, s := range []string{strings.Replace(example, "[URI]", "[ARGS]", 1), strings.Replace(example, "lowercase", "urldecode", 1), strings.Replace(example, "type: equals, value: GET", "type: equals, value: GET, not: true", 1), example + "unknown: true\n", example + "---\nname: other\n"} {
		r := Adapt([]byte(s))
		if r.Supported || r.Expression != nil || len(r.Reasons) == 0 {
			t.Fatalf("accepted unsupported YAML: %s", s)
		}
	}
}
func TestZonesAndTransforms(t *testing.T) {
	for _, x := range []struct{ zone, variable, value string }{{"HEADERS", "", "example.com"}, {"HEADERS", "Host", "example.com"}, {"HEADERS", "X-Test", "abc"}, {"URI_FULL", "", "/x?A=B"}, {"RAW_BODY", "", "body"}} {
		e := Expression{Zones: []string{x.zone}, Match: &Match{Type: "equals", Value: x.value}}
		if x.variable != "" {
			e.Variables = []string{x.variable}
		}
		c, err := Compile(e)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "http://example.com/x?A=B", nil)
		r.Header.Set("X-Test", "abc")
		if !c.Matches(r, []byte("body")) {
			t.Fatal(x)
		}
	}
}
