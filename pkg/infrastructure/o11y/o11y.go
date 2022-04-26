package o11y

import (
	"context"

	"github.com/diwise/service-chassis/pkg/infrastructure/o11y/logging"
	"github.com/diwise/service-chassis/pkg/infrastructure/o11y/tracing"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
)

func AddTraceIDToLoggerAndStoreInContext(span trace.Span, logger zerolog.Logger, ctx context.Context) (string, context.Context, zerolog.Logger) {
	log := logger
	traceID, ok := tracing.ExtractTraceID(span)

	if ok {
		log = log.With().Str("traceID", traceID).Logger()
	}

	ctx = logging.NewContextWithLogger(ctx, log)
	return traceID, ctx, log
}
