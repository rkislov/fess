package main

import "testing"

func TestIlikePatternEscapes(t *testing.T) {
	got := ilikePattern("100%_bad\\")
	want := "%100\\%\\_bad\\\\%"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParseOptionalHoursAll(t *testing.T) {
	_, use := parseOptionalHours("0", 168, true)
	if use {
		t.Fatal("expected no since for hours=0")
	}
}
