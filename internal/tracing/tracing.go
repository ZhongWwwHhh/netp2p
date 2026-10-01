// Package tracing wires optional OTLP trace export. When no endpoint is
// configured it installs nothing and the global tracer stays a no-op, so
// instrumentation calls cost effectively nothing.
package tracing

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

var enabled atomic.Bool

// Enabled reports whether an exporter was installed. Callers use it to skip
// span creation entirely when tracing is off.
func Enabled() bool {
	return enabled.Load()
}

// Setup installs an OTLP/HTTP tracer provider when endpoint is non-empty and
// returns a shutdown function. An empty endpoint returns a no-op shutdown and
// leaves the global provider untouched.
func Setup(ctx context.Context, endpoint, serviceVersion string) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if strings.TrimSpace(endpoint) == "" {
		return noop, nil
	}
	var options []otlptracehttp.Option
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return noop, fmt.Errorf("otel endpoint %q must be an http(s) URL or host:port", endpoint)
		}
		options = append(options, otlptracehttp.WithEndpointURL(endpoint))
	} else {
		options = append(options, otlptracehttp.WithEndpoint(endpoint), otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(ctx, options...)
	if err != nil {
		return noop, err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("netp2p"),
			semconv.ServiceVersion(serviceVersion),
		)),
	)
	otel.SetTracerProvider(provider)
	enabled.Store(true)
	return provider.Shutdown, nil
}
