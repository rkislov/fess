package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParseListPagination_defaults(t *testing.T) {
	r := &http.Request{URL: &url.URL{}}
	l, o, err := parseListPagination(r)
	if err != nil {
		t.Fatal(err)
	}
	if l != 100 || o != 0 {
		t.Fatalf("got limit=%d offset=%d", l, o)
	}
}

func TestParseListPagination_cap(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "limit=999&offset=10"}}
	l, o, err := parseListPagination(r)
	if err != nil {
		t.Fatal(err)
	}
	if l != 200 || o != 10 {
		t.Fatalf("got limit=%d offset=%d", l, o)
	}
}

func TestParseListPagination_invalid(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "limit=abc"}}
	_, _, err := parseListPagination(r)
	if err == nil {
		t.Fatal("want error")
	}
}
