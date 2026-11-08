package routing

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

func testPeer(id, path string, pathPriority, backendPriority int) ResolvedBackend {
	return ResolvedBackend{ID: id, BackendName: id, Backend: &url.URL{Scheme: "http", Host: id}, PathPrefix: path, PathPriority: pathPriority, BackendPriority: backendPriority}
}

func TestRoundRobinOnlyCyclesEquivalentRoutes(t *testing.T) {
	a, b := testPeer("a", "*", 10, 10), testPeer("b", "", 10, 10)
	alias := a
	alias.PathPrefix = "/"
	site := Snapshot{Sites: []ResolvedSite{{HostPattern: "*", Balance: BalanceConfig{Mode: "round_robin"}, Backends: []ResolvedBackend{
		testPeer("wrong-backend", "*", 10, 11), a, b, alias, testPeer("wrong-path", "*", 11, 1), testPeer("api", "/api", 99, 99),
	}}}}
	for i := 0; i < 6; i++ {
		if got := site.Match("example.com", "/other").BackendName; got != []string{"a", "b"}[i%2] {
			t.Fatalf("request %d selected %s", i, got)
		}
		if got := site.Match("example.com", "/api/v1").BackendName; got != "api" {
			t.Fatal(got)
		}
	}
	const requests = 60
	got := make(chan string, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() { defer wg.Done(); got <- site.Match("example.com", "/").BackendName }()
	}
	wg.Wait()
	close(got)
	n := map[string]int{}
	for peer := range got {
		n[peer]++
	}
	if n["a"] != 30 || n["b"] != 30 {
		t.Fatal(n)
	}
}

func TestHashAffinityAndMembershipChanges(t *testing.T) {
	makeSite := func(mode, key string, members ...string) Snapshot {
		peers := make([]ResolvedBackend, 0, len(members))
		for _, id := range members {
			peers = append(peers, testPeer(id, "*", 1, 1))
		}
		return Snapshot{Sites: []ResolvedSite{{HostPattern: "*", Balance: BalanceConfig{Mode: mode, Key: key}, Backends: peers}}}
	}
	for _, mode := range []string{"ip_hash", "path_hash", "header_hash", "cookie_hash"} {
		t.Run(mode, func(t *testing.T) {
			full := makeSite(mode, "Affinity", "a", "b", "c")
			reordered := makeSite(mode, "Affinity", "c", "b", "a")
			smaller := makeSite(mode, "Affinity", "b", "a")
			observed := map[string]bool{}
			for i := range 120 {
				key := strconv.Itoa(i)
				r := httptest.NewRequest("GET", "http://app.test/path/"+key+"?q=1", nil)
				r.Header.Set("Affinity", key)
				r.AddCookie(&http.Cookie{Name: "Affinity", Value: key})
				ip := fmt.Sprintf("192.0.2.%d", i+1)
				choose := func(s Snapshot) string { return s.MatchRequest("app.test", r, ip).BackendName }
				peer := choose(full)
				observed[peer] = true
				if choose(reordered) != peer || (peer != "c" && choose(smaller) != peer) {
					t.Fatalf("unstable assignment for %s", key)
				}
				r.URL.RawQuery = "q=2"
				if mode != "path_hash" {
					r.URL.Path = "/unrelated"
				}
				if mode != "ip_hash" {
					ip = "198.51.100.99"
				}
				if mode != "header_hash" {
					r.Header.Del("Affinity")
				}
				if mode != "cookie_hash" {
					r.Header.Del("Cookie")
				}
				if choose(full) != peer {
					t.Fatal("unrelated input changed the assignment")
				}
			}
			if len(observed) != 3 {
				t.Fatal("missing peer", observed)
			}
		})
	}
	ip := makeSite("ip_hash", "", "a", "b", "c")
	for _, mode := range []string{"header_hash", "cookie_hash"} {
		s := makeSite(mode, "session", "a", "b", "c")
		r := httptest.NewRequest("GET", "http://app.test/", nil)
		for i := range 25 {
			client := fmt.Sprintf("192.0.2.%d", i+1)
			if s.MatchRequest("app.test", r, client).BackendName != ip.MatchRequest("app.test", r, client).BackendName {
				t.Fatal(mode, "missing key did not fall back to IP")
			}
		}
	}
}
