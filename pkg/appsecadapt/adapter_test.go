package appsecadapt

import (
	"net/http/httptest"
	"testing"
)

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
