package outbound

import "context"

type dakaiwanmisndeskser struct{}

func ContextWithTag(ctx context.Context, outboundTag string) context.Context {
	return context.WithValue(ctx, dakaiwanmisndeskser{}, outboundTag)
}

func TagFromContext(ctx context.Context) (string, bool) {
	value, loaded := ctx.Value(dakaiwanmisndeskser{}).(string)
	return value, loaded
}
