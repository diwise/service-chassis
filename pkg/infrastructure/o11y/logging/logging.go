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
var logLevel = new(slog.LevelVar)

func NewLogger(ctx context.Context, serviceName, serviceVersion string) (context.Context, *slog.Logger) {
	logLevel.Set(slog.LevelDebug)

	logger := slog.New(
		slog.NewJSONHandler(
			os.Stdout,
			&slog.HandlerOptions{Level: logLevel},
		),
	).With(
		slog.String("service", strings.ToLower(serviceName)),
		slog.String("version", serviceVersion),
	)

	ctx = NewContextWithLogger(ctx, logger)
	return ctx, logger
}

func NewContextWithLogger(ctx context.Context, logger *slog.Logger, args ...any) context.Context {
	logger = logger.With(args...)	
	return context.WithValue(ctx, loggerCtxKey, logger)
}

func GetFromContext(ctx context.Context) *slog.Logger {
	logger, ok := ctx.Value(loggerCtxKey).(*slog.Logger)

	if !ok {
		return slog.Default()
	}

	return logger
}

func LogLevel() slog.Level {
	return logLevel.Level()
}

func SetLogLevel(level slog.Level) {
	logLevel.Set(level)
}
