package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	tracer trace.Tracer
)

// used in development. and testing.
func newConsoleExporter() (sdktrace.SpanExporter, error) {
	return stdouttrace.New()
}

// http otlp exporter
func newOTLPExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	insecureOpt := otlptracehttp.WithInsecure()
	endpointOpt := otlptracehttp.WithEndpointURL("http://localhost:4318")

	return otlptracehttp.New(ctx, insecureOpt, endpointOpt)
}

func newGeneralExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	//HTTP
	// endpointOpt := otlptracehttp.WithEndpointURL("http://localhost:4318")
	// insecureOpt := otlptracehttp.WithInsecure()

	//gRPC
	endpointOpt := otlptracegrpc.WithEndpointURL("http://localhost:4317")
	insecureOpt := otlptracegrpc.WithInsecure()

	// client := otlptracehttp.NewClient(endpointOpt, insecureOpt)

	client := otlptracegrpc.NewClient(endpointOpt, insecureOpt)

	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new otlptrace exporter: %w", err)
	}
	return exporter, nil
}

func newTraceProvider(exp sdktrace.SpanExporter) (*sdktrace.TracerProvider, error) {
	res1 := resource.Default()
	res2 := resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName("myapp"))

	resource, err := resource.Merge(res1, res2)
	if err != nil {
		return nil, fmt.Errorf("merging resources: %w", err)
	}

	limitBatcherOpt := sdktrace.WithMaxExportBatchSize(sdktrace.DefaultMaxExportBatchSize)
	timoutOpt := sdktrace.WithBatchTimeout(sdktrace.DefaultScheduleDelay * time.Millisecond)

	batcherOpt := sdktrace.WithBatcher(exp, limitBatcherOpt, timoutOpt)
	resorceOpt := sdktrace.WithResource(resource)

	//hardcoded routes
	exclude := map[string]struct{}{
		"/private": {},
	}

	samplerOpt := sdktrace.WithSampler(newEndpointExcluder(exclude, 0.5))

	provider := sdktrace.NewTracerProvider(batcherOpt, resorceOpt, samplerOpt)

	//set this provider as global trace provider
	otel.SetTracerProvider(provider)

	//use a customized propagator
	//For distributed systems, combining TraceContext and Baggage is common because:
	// TraceContext ensures trace information flows between services.
	// Baggage allows custom key-value metadata to propagate for additional context.
	compositeMapPropgator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(compositeMapPropgator)
	return provider, nil
}
func main() {
	ctx := context.Background()
	// exp, err := newOTLPExporter(ctx)
	// exp, err := newConsoleExporter()
	exp, err := newGeneralExporter(ctx)
	if err != nil {
		log.Fatal(err)
	}

	provider, err := newTraceProvider(exp)
	if err != nil {
		log.Fatal(err)
	}

	defer func() { _ = provider.Shutdown(ctx) }()

	otel.SetTracerProvider(provider)

	tracer = provider.Tracer("myapp") // service name.

	injectedTracer := addTracer(tracer)(http.HandlerFunc(helloHandler))
	withPropagation := tracePropagation(injectedTracer)

	server := http.Server{
		Addr: ":8000",
		//adding the root span for all reuqests.
		Handler: otelhttp.NewHandler(withPropagation, "requests"),
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT)

	go func() {
		log.Println("server running on port: 8000")
		log.Fatal(server.ListenAndServe())
	}()

	<-shutdown
	log.Println("shutting down...")

	server.Shutdown(ctx)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	ctx, span := addSpan(r.Context(), "HTTP Method: GET / ")
	defer span.End()

	traceID := getTraceID(r.Context())
	log.Println("Handler was hit by:", traceID)

	db(ctx)
	time.Sleep(time.Second * 1)

	w.Write([]byte("OK!"))
}

func db(ctx context.Context) {

	_, span := addSpan(ctx, "SQL SELECT POSTGRES")
	defer span.End()

	time.Sleep(time.Second * 2)
}

//==============================================================================
// Custom Sampler

type endpointExcluder struct {
	endpoints   map[string]struct{}
	probability float64
}

func newEndpointExcluder(endpoints map[string]struct{}, probability float64) endpointExcluder {
	return endpointExcluder{
		endpoints:   endpoints,
		probability: probability,
	}
}

func (epx endpointExcluder) Description() string {
	return "Custom Sampler"
}

// ShouldSample implements the sampler interface. It prevents the specified
// endpoints from being added to the trace.
func (epx endpointExcluder) ShouldSample(parameters sdktrace.SamplingParameters) sdktrace.SamplingResult {
	for i := range parameters.Attributes {
		// "http.target" represents the full request target as it appears in the HTTP request line,
		//typically including the path and query string (e.g., /home?user=123).
		if parameters.Attributes[i].Key == "http.target" {
			path := parameters.Attributes[i].Value.AsString()
			if _, ok := epx.endpoints[path]; ok {
				return sdktrace.SamplingResult{Decision: sdktrace.Drop}
			}
		}
	}

	return sdktrace.TraceIDRatioBased(epx.probability).ShouldSample(parameters)
}

// ==============================================================================
// Middlewares
type ctxKey int

const (
	tracerCtxKey = iota
	traceIDKey
)

func addTracerToCtx(ctx context.Context, tracer trace.Tracer) context.Context {
	return context.WithValue(ctx, tracerCtxKey, tracer)
}

func setTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey, traceID)
}

func getTraceID(ctx context.Context) string {
	traceID, ok := ctx.Value(traceIDKey).(string)
	if !ok {
		return "00000000000000000000000000000000"
	}
	return traceID
}

type Middleware func(next http.Handler) http.Handler

func addTracer(tracer trace.Tracer) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = addTracerToCtx(ctx, tracer)
			//grab the traceID from ctx
			traceID := trace.SpanFromContext(ctx).SpanContext().TraceID().String()
			ctx = setTraceID(ctx, traceID)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func tracePropagation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract trace context from incoming request headers
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		// Pass the updated context to the next handler
		next.ServeHTTP(w, r.WithContext(ctx))

		// Inject trace context into the response headers
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(w.Header()))
	})
}

// ==============================================================================
func addSpan(ctx context.Context, spanName string, keyvalues ...attribute.KeyValue) (context.Context, trace.Span) {
	tracer, ok := ctx.Value(tracerCtxKey).(trace.Tracer)
	if !ok || tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}

	ctx, span := tracer.Start(ctx, spanName)
	for _, kv := range keyvalues {
		span.SetAttributes(kv)
	}
	return ctx, span
}
