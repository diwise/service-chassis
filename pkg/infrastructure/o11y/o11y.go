package o11y

import (
	"context"

	"github.com/diwise/service-chassis/pkg/infrastructure/o11y/logging"
	"github.com/diwise/service-chassis/pkg/infrastructure/o11y/metrics"
	"github.com/diwise/service-chassis/pkg/infrastructure/o11y/tracing"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
)

type CleanupFunc func()

func Init(ctx context.Context, serviceName, serviceVersion string) (context.Context, zerolog.Logger, CleanupFunc) {
	ctx, logger := logging.NewLogger(ctx, serviceName, serviceVersion)
	logger.Info().Msg("starting up ...")

	cleanupMetrics, err := metrics.Init(ctx, logger, serviceName, serviceVersion)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to init metrics")
	}

	cleanupTracing, err := tracing.Init(ctx, logger, serviceName, serviceVersion)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to init tracing")
	}

	cleanup := func() {
		cleanupMetrics()
		cleanupTracing()
	}

	return ctx, logger, cleanup
}

func AddTraceIDToLoggerAndStoreInContext(span trace.Span, logger zerolog.Logger, ctx context.Context) (string, context.Context, zerolog.Logger) {
	log := logger
	traceID, ok := tracing.ExtractTraceID(span)

	if ok {
		log = log.With().Str("traceID", traceID).Logger()
	}

	ctx = logging.NewContextWithLogger(ctx, log)
	return traceID, ctx, log
}
