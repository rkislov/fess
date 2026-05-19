package auth

import "context"

type ctxKey int

const userKey ctxKey = 1

func WithClaims(ctx context.Context, c Claims) context.Context {
	return context.WithValue(ctx, userKey, c)
}

func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(userKey).(Claims)
	return c, ok
}

func ActorFromContext(ctx context.Context) string {
	if c, ok := ClaimsFromContext(ctx); ok && c.Username != "" {
		return c.Username
	}
	return "system"
}
