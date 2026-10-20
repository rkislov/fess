package threatfeed

import "testing"

func TestFilterBySources_emptySourceAlwaysPasses(t *testing.T) {
	rows := []ParsedRow{{Indicator: "1.1.1.1", Source: ""}}
	allow := map[string]struct{}{"other": {}}
	out := FilterBySources(rows, allow)
	if len(out) != 1 {
		t.Fatalf("got %d rows, want 1 (plain list must not be wiped by allowlist)", len(out))
	}
}

func TestFilterBySources_nonEmptySourceRespectsAllow(t *testing.T) {
	rows := []ParsedRow{{Indicator: "1.1.1.1", Source: "a"}}
	allow := map[string]struct{}{"b": {}}
	out := FilterBySources(rows, allow)
	if len(out) != 0 {
		t.Fatalf("got %d, want 0", len(out))
	}
	out2 := FilterBySources(rows, map[string]struct{}{"a": {}})
	if len(out2) != 1 {
		t.Fatalf("got %d, want 1", len(out2))
	}
}

func TestParsePlain_diffPrefixes(t *testing.T) {
	body := []byte("+1.1.1.1\n-2.2.2.2\n3.3.3.3\n")
	got, err := parsePlain(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (+add and plain; -skip)", len(got))
	}
	if got[0].Indicator != "1.1.1.1" || got[1].Indicator != "3.3.3.3" {
		t.Fatalf("unexpected %v", got)
	}
}
