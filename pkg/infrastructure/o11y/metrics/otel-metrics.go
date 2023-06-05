package metrics

import (
	"context"
	"os"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

type CleanupFunc func()

func Init(ctx context.Context, logger zerolog.Logger, serviceName, serviceVersion string) (CleanupFunc, error) {
	exporterEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	cleanupFunc := func() {}

	if exporterEndpoint != "" {
		exp, err := otlpmetrichttp.New(ctx)
		if err != nil {
			return cleanupFunc, err
		}

		meterProvider := metric.NewMeterProvider(
			metric.WithResource(resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String(serviceName),
				semconv.ServiceVersionKey.String(serviceVersion),
			)),
			metric.WithReader(
				metric.NewPeriodicReader(exp, metric.WithInterval(10*time.Second)),
			),
		)

		cleanupFunc = func() {
			err := meterProvider.Shutdown(ctx)
			if err != nil {
				logger.Error().Err(err).Msg("failed to shutdown otel meter provider")
			}
		}

		otel.SetMeterProvider(meterProvider)
	}

	return cleanupFunc, nil
}
