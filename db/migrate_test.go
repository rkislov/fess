package db

import "testing"

func TestListMigrations(t *testing.T) {
	ms, err := listMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) < 9 {
		t.Fatalf("expected at least 9 numbered migrations, got %d", len(ms))
	}
	for i := 1; i < len(ms); i++ {
		if ms[i].version <= ms[i-1].version {
			t.Fatalf("not sorted: %v before %v", ms[i-1], ms[i])
		}
	}
}
