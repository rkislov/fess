package ipbypass

import (
	"context"
	"strings"

	"fence/pkg/ratelimit"

	"fence/internal/runtimebus"
)

// ClearBotRateLimitKeys removes bot protection and system rate-limit state for a client IP.
func ClearBotRateLimitKeys(ctx context.Context, state *runtimebus.Client, clientIP string) {
	if state == nil {
		return
	}
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		return
	}
	_ = state.Del(ctx, "fence:bot:rl:ip:"+clientIP).Err()
	_ = state.Del(ctx, "fence:bot:ts:"+clientIP).Err()
	for _, prefix := range []string{"fence:bot:rl:iph:" + clientIP + ":", "fence:bot:rl:ipp:" + clientIP + ":"} {
		iter := state.Scan(ctx, 0, prefix+"*", 128).Iterator()
		for iter.Next(ctx) {
			_ = state.Del(ctx, iter.Val()).Err()
		}
	}
	ratelimit.ClearKeysForIP(ctx, state, clientIP)
}
