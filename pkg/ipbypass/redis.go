package ipbypass

import (
	"context"
	"strings"

	"github.com/redis/go-redis/v9"
)

// ClearBotRateLimitKeys removes bot protection rate-limit state for a client IP.
func ClearBotRateLimitKeys(ctx context.Context, rdb *redis.Client, clientIP string) {
	if rdb == nil {
		return
	}
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		return
	}
	_ = rdb.Del(ctx, "fence:bot:rl:ip:"+clientIP).Err()
	_ = rdb.Del(ctx, "fence:bot:ts:"+clientIP).Err()
	for _, prefix := range []string{"fence:bot:rl:iph:" + clientIP + ":", "fence:bot:rl:ipp:" + clientIP + ":"} {
		iter := rdb.Scan(ctx, 0, prefix+"*", 128).Iterator()
		for iter.Next(ctx) {
			_ = rdb.Del(ctx, iter.Val()).Err()
		}
	}
}
