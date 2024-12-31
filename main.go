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

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
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
	endpointOpt := otlptracehttp.WithEndpointURL("http://localhost:4318")
	insecureOpt := otlptracehttp.WithInsecure()

	client := otlptracehttp.NewClient(endpointOpt, insecureOpt)

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
	return sdktrace.NewTracerProvider(batcherOpt, resorceOpt), nil
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

	tracer = provider.Tracer("myapp")

	server := http.Server{
		Addr:    ":8000",
		Handler: http.HandlerFunc(helloHandler),
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
	ctx, span := tracer.Start(r.Context(), "HTTP GET /")
	defer span.End()

	log.Println("Handler was hit by:", r.RemoteAddr)

	db(ctx)
	time.Sleep(time.Second * 1)

	w.Write([]byte("OK!"))
}

func db(ctx context.Context) {
	_, span := tracer.Start(ctx, "SQL SELECT")
	defer span.End()

	time.Sleep(time.Second * 2)
}
