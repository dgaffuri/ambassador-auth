package main

import (
	"log"
	"net/http"

	zipkin "github.com/openzipkin/zipkin-go"
	zipkinhttp "github.com/openzipkin/zipkin-go/middleware/http"
	"github.com/openzipkin/zipkin-go/model"
	reporterhttp "github.com/openzipkin/zipkin-go/reporter/http"
)

var middleware func(http.Handler) http.Handler

func init() {

	if config.TracingURL == "" {
		return
	}

	// The reporter sends traces to zipkin server
	reporter := reporterhttp.NewReporter(config.TracingURL + "/api/v2/spans")

	// Local endpoint represent the local service information
	tracingService := config.TracingService
	if tracingService == "" {
		tracingService = "ambassador-auth-oidc"
	}
	localEndpoint := &model.Endpoint{ServiceName: tracingService}

	// Sampler tells you which traces are going to be sampled or not. In this case we will record 100% (1.00) of traces.
	sampler, err := zipkin.NewCountingSampler(1)
	if err != nil {
		log.Println("error creating zipkin sampler:", err.Error())
		return
	}

	// Create tracer
	tracer, err := zipkin.NewTracer(
		reporter,
		zipkin.WithSampler(sampler),
		zipkin.WithLocalEndpoint(localEndpoint),
	)
	if err != nil {
		log.Println("error creating zipkin tracer:", err.Error())
		return
	}

	// Create middleware
	middleware = zipkinhttp.NewServerMiddleware(tracer)

	// Set HTTP default client transport
	http.DefaultClient.Transport, err = zipkinhttp.NewTransport(
		tracer,
		zipkinhttp.TransportTrace(true),
	)
}
