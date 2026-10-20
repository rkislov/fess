// fess-load is a repeatable closed-loop HTTP load generator. Run against a
// dedicated test installation: it generates real traffic and persistent logs.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

func main() {
	target := flag.String("url", "", "target URL")
	host := flag.String("host", "", "override Host")
	duration := flag.Duration("duration", 10*time.Second, "measurement duration")
	concurrency := flag.Int("concurrency", 16, "concurrent HTTP workers")
	method := flag.String("method", "GET", "HTTP method")
	bodyBytes := flag.Int("body-bytes", 0, "synthetic upload size")
	serve := flag.String("serve", "", "serve a small test upstream instead of generating load")
	flag.Parse()
	if *serve != "" {
		err := http.ListenAndServe(*serve, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "origin-ok")
		}))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *target == "" || *duration <= 0 || *concurrency < 1 || *bodyBytes < 0 {
		flag.Usage()
		os.Exit(2)
	}
	tr := &http.Transport{MaxIdleConns: *concurrency, MaxIdleConnsPerHost: *concurrency, MaxConnsPerHost: *concurrency, DisableCompression: true}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	defer tr.CloseIdleConnections()
	body := bytes.Repeat([]byte("a"), *bodyBytes)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var samples []float64
	codes := map[int]int64{}
	var failures int64
	var errorExamples []string
	var totalBytes int64
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []float64
			localCodes := map[int]int64{}
			var errs, bytesRead int64
			var examples []string
			for ctx.Err() == nil {
				req, err := http.NewRequest(*method, *target, bytes.NewReader(body))
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return
				}
				if *host != "" {
					req.Host = *host
				}
				if len(body) > 0 {
					req.Header.Set("Content-Type", "application/octet-stream")
				}
				before := time.Now()
				response, err := client.Do(req)
				if err == nil {
					n, e := io.Copy(io.Discard, response.Body)
					response.Body.Close()
					bytesRead += n
					if e != nil {
						err = e
					} else {
						localCodes[response.StatusCode]++
					}
				}
				local = append(local, float64(time.Since(before))/float64(time.Millisecond))
				if err != nil {
					errs++
					if len(examples) < 1 {
						examples = append(examples, err.Error())
					}
				}
			}
			mu.Lock()
			samples = append(samples, local...)
			for code, n := range localCodes {
				codes[code] += n
			}
			failures += errs
			totalBytes += bytesRead
			for _, e := range examples {
				if len(errorExamples) < 3 {
					errorExamples = append(errorExamples, e)
				}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	sort.Float64s(samples)
	percentile := func(q float64) float64 {
		if len(samples) == 0 {
			return 0
		}
		i := int(float64(len(samples)-1) * q)
		return samples[i]
	}
	result := map[string]any{"url": *target, "method": *method, "concurrency": *concurrency, "duration_requested_seconds": duration.Seconds(), "elapsed_seconds": elapsed, "requests": len(samples), "requests_per_second": float64(len(samples)) / elapsed, "p50_ms": percentile(.50), "p95_ms": percentile(.95), "p99_ms": percentile(.99), "max_ms": percentile(1), "transport_errors": failures, "status_codes": codes, "response_bytes": totalBytes, "error_examples": errorExamples, "body_bytes": *bodyBytes, "model": "closed-loop; fixed workers; includes connection setup; in-flight requests drain after duration"}
	json.NewEncoder(os.Stdout).Encode(result)
	if failures > 0 {
		os.Exit(1)
	}
}
