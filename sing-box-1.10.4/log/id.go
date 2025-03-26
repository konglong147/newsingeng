package log

import (
	"context"
	"math/rand"
	"time"

	"github.com/sagernet/sing/common/random"
)

func init() {
	random.InitializeSeed()
}
type Level = uint8
type idKey struct{}
type ID struct {
	ID        uint32
	CreatedAt time.Time
}
type Options struct {

}

func Chuagjianxindeidse(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*idKey)(nil), ID{
		ID:        rand.Uint32(),
		CreatedAt: time.Now(),
	})
}

const (
	LevelPanic Level = iota
	LevelFatal
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)
func New(yousuocanshu Options) (Factory, error) {
	factory := Xindemorenfater(
	)
	return factory, nil
}


