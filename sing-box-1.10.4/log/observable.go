package log

import (
	"context"

)

var _ Factory = (*morenfanseser)(nil)

type morenfanseser struct {
}

func Xindemorenfater(
	
) ObservableFactory {
	factory := &morenfanseser{

	}
	return factory
}
func (f *morenfanseser) NewLogger(tag string) ContextLogger {
	return &guanchaSlouser{f, tag}
}

var _ ContextLogger = (*guanchaSlouser)(nil)

type guanchaSlouser struct {
	*morenfanseser
	tag string
}

func (l *guanchaSlouser) Log(ctx context.Context, level Level, args []any) {
	
}

func (l *guanchaSlouser) Trace(args ...any) {
	l.TraceContext(context.Background(), args...)
}

func (l *guanchaSlouser) Debug(args ...any) {
	l.DebugContext(context.Background(), args...)
}

func (l *guanchaSlouser) Info(args ...any) {
	l.InfoContext(context.Background(), args...)
}

func (l *guanchaSlouser) Warn(args ...any) {
	l.WarnContext(context.Background(), args...)
}

func (l *guanchaSlouser) Error(args ...any) {
	l.ErrorContext(context.Background(), args...)
}

func (l *guanchaSlouser) Fatal(args ...any) {
	l.FatalContext(context.Background(), args...)
}

func (l *guanchaSlouser) Panic(args ...any) {
	l.PanicContext(context.Background(), args...)
}

func (l *guanchaSlouser) TraceContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelTrace, args)
}

func (l *guanchaSlouser) DebugContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelDebug, args)
}

func (l *guanchaSlouser) InfoContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelInfo, args)
}

func (l *guanchaSlouser) WarnContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelWarn, args)
}

func (l *guanchaSlouser) ErrorContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelError, args)
}

func (l *guanchaSlouser) FatalContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelFatal, args)
}

func (l *guanchaSlouser) PanicContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelPanic, args)
}
