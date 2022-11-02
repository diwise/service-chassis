package metrics

import (
	"context"
	"os"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/sdk/metric"
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

		meterProvider := metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(exp)))
		cleanupFunc = func() {
			err := meterProvider.Shutdown(ctx)
			if err != nil {
				logger.Error().Err(err).Msg("failed to shutdown otel meter provider")
			}
		}

		global.SetMeterProvider(meterProvider)
	}

	return cleanupFunc, nil
}
