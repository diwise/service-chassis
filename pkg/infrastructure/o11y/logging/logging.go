package logging

import (
	"context"
	"os"
	"strings"

	"log/slog"
)

type loggerContextKey struct {
	name string
}

var loggerCtxKey = &loggerContextKey{"logger"}

func NewLogger(ctx context.Context, serviceName, serviceVersion string) (context.Context, *slog.Logger) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(
		slog.String("service", strings.ToLower(serviceName)),
		slog.String("version", serviceVersion),
	)

	ctx = NewContextWithLogger(ctx, logger)
	return ctx, logger
}

func NewContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	ctx = context.WithValue(ctx, loggerCtxKey, logger)
	return ctx
}

func GetFromContext(ctx context.Context) *slog.Logger {
	logger, ok := ctx.Value(loggerCtxKey).(*slog.Logger)

	if !ok {
		return slog.Default()
	}

	return logger
}
