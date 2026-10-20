// Package logbatch batches gateway logs in a bounded, process-local queue.
// Queue saturation applies backpressure; failed batches are retried, not dropped.
// An abrupt process/host failure can lose uncommitted queued records. Select
// FESS_LOG_MODE=sync when commit-before-response durability is required.
package logbatch

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fencedb "fence/db"
	"fence/pkg/prommetrics"
)

var stampedQueries sync.Map
var writers sync.Map // *sql.DB -> *Writer
var ErrClosed = errors.New("log writer closed")

type record struct {
	query   string
	args    []any
	barrier chan error
	stop    bool
}
type Writer struct {
	db        *sql.DB
	queue     chan record
	done      chan struct{}
	cancel    context.CancelFunc
	mu        sync.RWMutex
	closed    bool
	pending   atomic.Int64
	failure   atomic.Pointer[string]
	batchSize int
	interval  time.Duration
}

func Start(db *sql.DB) (*Writer, error) {
	mode := os.Getenv("FESS_LOG_MODE")
	if mode == "sync" {
		return nil, nil
	}
	if mode != "" && mode != "batch" {
		return nil, fmt.Errorf("FESS_LOG_MODE must be batch or sync")
	}
	if _, ok := writers.Load(db); ok {
		return nil, fmt.Errorf("log writer already registered")
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &Writer{db: db, queue: make(chan record, 8192), done: make(chan struct{}), cancel: cancel, batchSize: 256, interval: 20 * time.Millisecond}
	writers.Store(db, w)
	go w.run(ctx)
	return w, nil
}

// Exec only queues known INSERT statements from gateway log producers. Values are
// immutable strings/scalars captured before the request returns.
func Exec(ctx context.Context, db *sql.DB, query string, args ...any) error {
	query, args = eventTime(query, args)
	value, ok := writers.Load(db)
	if !ok {
		_, err := db.ExecContext(ctx, query, args...)
		return err
	}
	w := value.(*Writer)
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return ErrClosed
	}
	// Count before publishing so a fast consumer cannot make the gauge negative.
	w.pending.Add(1)
	prommetrics.LogPending.Inc()
	select {
	case w.queue <- record{query: query, args: args}:
		prommetrics.LogEnqueued.Inc()
		return nil
	case <-ctx.Done():
		w.pending.Add(-1)
		prommetrics.LogPending.Dec()
		prommetrics.LogRejected.Inc()
		return ctx.Err()
	case <-w.done:
		w.pending.Add(-1)
		prommetrics.LogPending.Dec()
		prommetrics.LogRejected.Inc()
		return ErrClosed
	}
}
func Flush(ctx context.Context, db *sql.DB) error {
	value, ok := writers.Load(db)
	if !ok {
		return nil
	}
	return value.(*Writer).barrier(ctx, false)
}
func (w *Writer) barrier(ctx context.Context, stop bool) error {
	ack := make(chan error, 1)
	w.mu.RLock()
	if w.closed && !stop {
		w.mu.RUnlock()
		return ErrClosed
	}
	select {
	case w.queue <- record{barrier: ack, stop: stop}:
		w.mu.RUnlock()
	case <-ctx.Done():
		w.mu.RUnlock()
		return ctx.Err()
	case <-w.done:
		w.mu.RUnlock()
		return ErrClosed
	}
	select {
	case err := <-ack:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		if w.pending.Load() == 0 {
			return nil
		}
		return fmt.Errorf("log writer stopped with %d pending records", w.pending.Load())
	}
}
func (w *Writer) Close(ctx context.Context) error {
	stop := context.AfterFunc(ctx, w.cancel)
	defer stop()
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		select {
		case <-w.done:
			if n := w.pending.Load(); n != 0 {
				return fmt.Errorf("log writer stopped with %d uncommitted records", n)
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	w.closed = true
	w.mu.Unlock()
	err := w.barrier(ctx, true)
	if err != nil {
		w.cancel()
	}
	<-w.done
	writers.Delete(w.db)
	if n := w.pending.Load(); n != 0 {
		return fmt.Errorf("log writer stopped with %d uncommitted records: %w", n, err)
	}
	return err
}
func CloseAll(ctx context.Context) error {
	var errs []error
	writers.Range(func(key, value any) bool {
		if err := value.(*Writer).Close(ctx); err != nil {
			errs = append(errs, err)
		}
		return true
	})
	return errors.Join(errs...)
}
func (w *Writer) run(ctx context.Context) {
	defer close(w.done)
	defer w.cancel()
	tick := time.NewTicker(w.interval)
	defer tick.Stop()
	batch := make([]record, 0, w.batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		for {
			attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
			err := w.commit(attempt, batch)
			cancel()
			if err == nil {
				n := int64(len(batch))
				w.pending.Add(-n)
				prommetrics.LogPending.Sub(float64(n))
				prommetrics.LogCommitted.Add(float64(n))
				prommetrics.LogBatches.Inc()
				w.failure.Store(nil)
				batch = batch[:0]
				return nil
			}
			msg := err.Error()
			w.failure.Store(&msg)
			prommetrics.LogWriteErrors.Inc()
			log.Printf("log batch retained (%d rows), retrying: %v", len(batch), err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-w.queue:
			if r.barrier != nil {
				err := flush()
				r.barrier <- err
				if err != nil || r.stop {
					return
				}
				continue
			}
			batch = append(batch, r)
			if len(batch) >= w.batchSize {
				if flush() != nil {
					return
				}
			}
		case <-tick.C:
			if flush() != nil {
				return
			}
		}
	}
}

var placeholder = regexp.MustCompile(`\$(\d+)`)
var insertValues = regexp.MustCompile(`(?is)^(\s*INSERT\s+INTO\s+.+?\s+VALUES\s*)(\(.+\))\s*$`)

func (w *Writer) commit(ctx context.Context, records []record) error {
	// Log tables have no inter-table dependencies. Keep per-query order while
	// combining rows into one INSERT per statement shape inside one transaction.
	groups := map[string][]record{}
	var order []string
	for _, r := range records {
		if _, ok := groups[r.query]; !ok {
			order = append(order, r.query)
		}
		groups[r.query] = append(groups[r.query], r)
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, query := range order {
		group := groups[query]
		if fencedb.IsSQLite(w.db) {
			stmt, err := tx.PrepareContext(ctx, query)
			if err != nil {
				return err
			}
			for _, r := range group {
				if _, err = stmt.ExecContext(ctx, r.args...); err != nil {
					stmt.Close()
					return err
				}
			}
			if err = stmt.Close(); err != nil {
				return err
			}
			continue
		}
		parts := insertValues.FindStringSubmatch(query)
		if parts == nil {
			return fmt.Errorf("unsupported log INSERT")
		}
		var values []string
		var args []any
		for _, r := range group {
			offset := len(args)
			values = append(values, placeholder.ReplaceAllStringFunc(parts[2], func(s string) string { n, _ := strconv.Atoi(s[1:]); return "$" + strconv.Itoa(n+offset) }))
			args = append(args, r.args...)
		}
		if _, err = tx.ExecContext(ctx, parts[1]+strings.Join(values, ","), args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Capture event time before enqueue, rather than stamping all rows with the
// eventual batch commit time. The immutable statement shape is cached.
func eventTime(query string, args []any) (string, []any) {
	n := len(args)
	known := strings.Contains(query, "INSERT INTO waf_logs(") || strings.Contains(query, "INSERT INTO proxy_access_logs(") || strings.Contains(query, "INSERT INTO malware_scan_logs(")
	out := make([]any, n, n+1)
	copy(out, args)
	if !known {
		return query, out
	}
	if cached, ok := stampedQueries.Load(query); ok {
		return cached.(string), append(out, time.Now().UTC())
	}
	values := strings.Index(query, "VALUES")
	columnsEnd := strings.LastIndex(query[:values], ")")
	valuesEnd := strings.LastIndex(query, ")")
	stamped := query[:columnsEnd] + ", created_at" + query[columnsEnd:valuesEnd] + ", $" + strconv.Itoa(n+1) + query[valuesEnd:]
	stampedQueries.Store(query, stamped)
	return stamped, append(out, time.Now().UTC())
}
