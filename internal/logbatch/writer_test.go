package logbatch

import (
	"context"
	fencedb "fence/db"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const insert = `INSERT INTO waf_logs(request_id, action, details) VALUES($1,$2,$3::jsonb)`

func TestConcurrentBatchFlushAndShutdown(t *testing.T) {
	ctx := context.Background()
	db, err := fencedb.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = fencedb.ApplyMigrations(ctx, db); err != nil {
		t.Fatal(err)
	}
	w, err := Start(db)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := Exec(ctx, db, insert, "test", "block", `{"key":"value"}`); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = Flush(timeout, db); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM waf_logs`).Scan(&count); err != nil || count != 1600 {
		t.Fatalf("missing records: %d %v", count, err)
	}
	if err = Exec(ctx, db, insert, "tail", "block", `{}`); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(timeout); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM waf_logs`).Scan(&count); err != nil || count != 1601 {
		t.Fatalf("shutdown lost tail: %d %v", count, err)
	}
}
func TestFailedBatchRetainedAndRetried(t *testing.T) {
	ctx := context.Background()
	db, err := fencedb.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "retry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Missing table injects a transactional failure; creating it allows the same
	// queued batch to succeed without re-enqueueing any event.
	w, err := Start(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = Exec(ctx, db, `INSERT INTO events(value) VALUES($1)`, "retained"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for w.failure.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("failure was not observed")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err = db.Exec(`CREATE TABLE events(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	timeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err = Flush(timeout, db); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(timeout); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM events WHERE value='retained'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retry lost/duplicated event: %d %v", count, err)
	}
}
func TestBoundedQueueBackpressure(t *testing.T) {
	// An intentionally unstarted writer fills a one-slot queue deterministically.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	db, err := fencedb.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "bounded.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w := &Writer{queue: make(chan record, 1), done: make(chan struct{})}
	writers.Store(db, w)
	defer writers.Delete(db)
	if err = Exec(ctx, db, `INSERT INTO events(value) VALUES($1)`, "first"); err != nil {
		t.Fatal(err)
	}
	if err = Exec(ctx, db, `INSERT INTO events(value) VALUES($1)`, "second"); err == nil {
		t.Fatal("full queue must block until cancellation, not silently drop")
	}
	if w.pending.Load() != 1 {
		t.Fatalf("pending count=%d", w.pending.Load())
	}
}

func TestShutdownDeadlineUnblocksFullQueue(t *testing.T) {
	ctx := context.Background()
	db, err := fencedb.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "shutdown.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	worker, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()
	w := &Writer{db: db, queue: make(chan record, 1), done: make(chan struct{}), cancel: cancelWorker, batchSize: 1, interval: time.Millisecond}
	writers.Store(db, w)
	defer writers.Delete(db)
	go w.run(worker)
	if err = Exec(ctx, db, `INSERT INTO missing_table(value) VALUES($1)`, "first"); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for w.failure.Load() == nil {
		if time.Now().After(until) {
			t.Fatal("missing injected failure")
		}
		time.Sleep(time.Millisecond)
	}
	if err = Exec(ctx, db, `INSERT INTO missing_table(value) VALUES($1)`, "second"); err != nil {
		t.Fatal(err)
	}
	producer := make(chan error, 1)
	go func() { producer <- Exec(ctx, db, `INSERT INTO missing_table(value) VALUES($1)`, "third") }()
	until = time.Now().Add(time.Second)
	for w.pending.Load() != 3 {
		if time.Now().After(until) {
			t.Fatal("producer did not reach backpressure")
		}
		time.Sleep(time.Millisecond)
	}
	timeout, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	closeDone := make(chan error, 1)
	go func() { closeDone <- w.Close(timeout) }()
	select {
	case err := <-closeDone:
		if err == nil {
			t.Fatal("must report uncommitted rows")
		}
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked behind a blocked producer")
	}
	select {
	case err := <-producer:
		if err == nil {
			t.Fatal("blocked producer unexpectedly accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("producer did not unblock")
	}
}
