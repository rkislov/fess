package botprotection

import "testing"

func TestParseASNList(t *testing.T) {
	asns, err := ParseASNList([]byte("15169\nAS396982\n# comment\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(asns) != 2 {
		t.Fatalf("len = %d", len(asns))
	}
}
