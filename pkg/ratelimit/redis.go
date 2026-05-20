package ratelimit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Check increments a sliding window counter and reports whether the request is allowed.
func Check(ctx context.Context, rdb *redis.Client, cfg Config, clientIP, host, path, backendName string) (allowed bool, detail string) {
	if !cfg.Enabled || rdb == nil {
		return true, ""
	}
	cfg = NormalizeConfig(cfg)
	key := RedisKey(cfg.Scope, clientIP, host, path, backendName)
	window := time.Duration(cfg.WindowSec) * time.Second
	limit := int64(cfg.RequestsPerWindow)

	pipe := rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return true, ""
	}
	n, err := incr.Result()
	if err != nil {
		return true, ""
	}
	if n > limit {
		return false, fmt.Sprintf("rate limit %d/%d per %ds (%s)", n, limit, cfg.WindowSec, cfg.Scope)
	}
	return true, ""
}

// RedisKey builds the counter key for the given scope.
func RedisKey(scope, clientIP, host, path, backendName string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "ip":
		return "fence:rl:ip:" + clientIP
	case "ip_path":
		return "fence:rl:ipp:" + clientIP + ":" + host + ":" + path
	case "backend":
		return "fence:rl:be:" + clientIP + ":" + backendName + ":" + path
	default:
		return "fence:rl:iph:" + clientIP + ":" + host
	}
}

// ClearKeysForIP removes rate-limit counters for a client IP (e.g. on bypass unblock).
func ClearKeysForIP(ctx context.Context, rdb *redis.Client, clientIP string) {
	if rdb == nil {
		return
	}
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		return
	}
	_ = rdb.Del(ctx, "fence:rl:ip:"+clientIP).Err()
	for _, prefix := range []string{
		"fence:rl:iph:" + clientIP + ":",
		"fence:rl:ipp:" + clientIP + ":",
		"fence:rl:be:" + clientIP + ":",
	} {
		iter := rdb.Scan(ctx, 0, prefix+"*", 128).Iterator()
		for iter.Next(ctx) {
			_ = rdb.Del(ctx, iter.Val()).Err()
		}
	}
}
