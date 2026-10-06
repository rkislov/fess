package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fence/pkg/clientip"
	"fence/pkg/routing"
)

func TestWriteFESSSplashContainsAuthor(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFESSSplash(rr)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	for _, s := range []string{"FESS", "Роман Сергеевич Кислов", "Roman Sergeyevich Kislov", "/_fess/art/splash.jpg"} {
		if !strings.Contains(body, s) {
			t.Fatalf("missing %q in splash html", s)
		}
	}
}

func TestWriteFESSErrorBlockedArt(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFESSError(rr, http.StatusForbidden, pageBlocked, "Заблокировано", "тест")
	if rr.Code != 403 {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "/_fess/art/blocked.jpg") {
		t.Fatal("expected blocked mural")
	}
}

func TestServeBrandAsset(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/_fess/art/splash.jpg", nil)
	rr := httptest.NewRecorder()
	if !serveBrandAsset(rr, req) {
		t.Fatal("expected handled")
	}
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Fatalf("content-type %s", ct)
	}
	if rr.Body.Len() < 1000 {
		t.Fatal("expected jpeg bytes")
	}
}

func TestMaybeServeSplash(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ok := maybeServeSplash(rr, req, routing.MatchResult{Splash: true}, nil, clientip.ParseTrustedProxies(""))
	if !ok || rr.Code != 200 {
		t.Fatalf("ok=%v code=%d", ok, rr.Code)
	}
}
