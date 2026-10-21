package gateway

import (
	"net/http/httptest"
	"testing"
)

func TestHTTPSRedirectLimitsHosts(t *testing.T) {
	for _, tc := range []struct {
		host string
		want int
	}{{"app.test", 308}, {"app.test:80", 308}, {"evil.test", 200}} {
		r := httptest.NewRequest("GET", "http://"+tc.host+"/p?q=1", nil)
		w := httptest.NewRecorder()
		httpsRedirect(w, r, map[string]string{"app.test": "app.test"}, nil)
		if w.Code != tc.want {
			t.Fatal(tc, w.Code)
		}
		if tc.want == 308 && w.Header().Get("Location") != "https://app.test/p?q=1" {
			t.Fatal(w.Header())
		}
	}
}
