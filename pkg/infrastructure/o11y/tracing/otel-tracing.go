package tracing

import (
	"context"
	"os"

	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.opentelemetry.io/otel/trace"
)

type CleanupFunc func()

func Init(ctx context.Context, logger *slog.Logger, serviceName, serviceVersion string) (CleanupFunc, error) {

	exporterEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	cleanupFunc := func() {}

	if exporterEndpoint != "" {
		client := otlptracehttp.NewClient()
		exporter, err := otlptrace.New(ctx, client)
		if err != nil {
			msg := "failed to create OTLP trace exporter"
			logger.Error(msg, "err", err.Error())
			panic(msg)
		}

		tracerProvider := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(newResource(serviceName, serviceVersion)),
		)
		otel.SetTracerProvider(tracerProvider)
		otel.SetTextMapPropagator(propagation.TraceContext{})

		cleanupFunc = func() {
			if err := tracerProvider.Shutdown(ctx); err != nil {
				logger.Error("error while stopping tracer provider", "err", err.Error())
			}
		}
	}

	return cleanupFunc, nil
}

func AddEvent(ctx context.Context, name string, options ...trace.EventOption) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, options...)
}

func CurrentTraceID(ctx context.Context) string {
	t := trace.SpanFromContext(ctx).SpanContext().TraceID()
	if !t.IsValid() {
		return ""
	}
	return t.String()
}

func ExtractTraceID(span trace.Span) (string, bool) {
	traceID := span.SpanContext().TraceID()

	if !traceID.IsValid() {
		return "", false
	}

	return traceID.String(), true
}

func RecordAnyErrorAndEndSpan(err error, span trace.Span) {
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
	}
	span.End()
}

func SetSpanStatus(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		} else {
			span.SetStatus(codes.Ok, "")
		}
	}
}

func SetSpanStatusOnExit(ctx context.Context, getError func() error) func() {
	return func() {
		SetSpanStatus(ctx, getError())
	}
}

func Start(ctx context.Context, tracerName, spanName string, getError func() error, opts ...trace.SpanStartOption) (context.Context, func()) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return ctx, func() {}
	}

	ctx, subspan := span.TracerProvider().Tracer(tracerName).Start(ctx, spanName, opts...)

	return ctx, func() {
		var err error
		if getError != nil {
			err = getError()
		}
		SetSpanStatus(ctx, err)
		subspan.End()
	}
}

// newResource returns a resource describing this application.
func newResource(serviceName, version string) *resource.Resource {
	return resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(serviceName),
		semconv.ServiceVersionKey.String(version),
	)
}

type headersCarrier map[string]interface{}

func (a headersCarrier) Get(key string) string {
	v, ok := a[key]
	if !ok {
		return ""
	}
	return v.(string)
}

func (a headersCarrier) Set(key string, value string) {
	a[key] = value
}

func (a headersCarrier) Keys() []string {
	i := 0
	r := make([]string, len(a))

	for k := range a {
		r[i] = k
		i++
	}

	return r
}

// InjectHeaders injects the tracing info from the context into a new header map
func InjectHeaders(ctx context.Context) map[string]interface{} {
	h := make(headersCarrier)
	otel.GetTextMapPropagator().Inject(ctx, h)
	return h
}

// ExtractHeaders extracts the tracing info from the header and puts it into the context
func ExtractHeaders(ctx context.Context, headers map[string]interface{}) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, headersCarrier(headers))
}
