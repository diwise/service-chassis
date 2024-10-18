package servicerunner_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diwise/service-chassis/pkg/infrastructure/net/http/handlers"
	"github.com/diwise/service-chassis/pkg/infrastructure/servicerunner"
	"github.com/matryer/is"
)

var WithStartingTimeout = servicerunner.WithStartingTimeout
var OnStarting = servicerunner.OnStarting
var OnRunning = servicerunner.OnRunning
var OnShutdown = servicerunner.OnShutdown

var WithHTTPServeMux = servicerunner.WithHTTPServeMux
var WithK8SLivenessProbe = servicerunner.WithK8SLivenessProbe
var WithK8SReadinessProbes = servicerunner.WithK8SReadinessProbes
var OnMuxInit = servicerunner.OnMuxInit

func TestStartingAndStopping(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)

	ctx, r := servicerunner.New(ctx, OnRunning(stopRunner))

	is.NoErr(r.Run(ctx, nil))
}

func TestStartupAndShutdownHooksAreCalled(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)
	var startupCalled atomic.Bool
	var shutdownCalled atomic.Bool

	ctx, r := servicerunner.New(ctx,
		OnRunning(stopRunner),
		OnStarting(func(_ context.Context) error {
			startupCalled.Store(true)
			return nil
		}),
		OnShutdown(func(_ context.Context) error {
			shutdownCalled.Store(true)
			return nil
		}),
	)

	is.NoErr(r.Run(ctx, nil))
	is.True(startupCalled.Load())  // startup hook should have been called
	is.True(shutdownCalled.Load()) // shutdown hook should have been called
}

func TestPresentsIdentifierOnMuxInit(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)
	const expectedMuxName string = "therearemanymuxeslikeitbutthisoneismine"

	ctx, r := servicerunner.New(ctx,
		OnRunning(stopRunner),
		WithHTTPServeMux(
			expectedMuxName,
			OnMuxInit(func(_ context.Context, identifier string, _ string, _ *http.ServeMux) error {
				is.Equal(expectedMuxName, identifier)
				return nil
			}),
		),
	)

	is.NoErr(r.Run(ctx, nil))
}

func TestK8SLivenessProbe(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)
	var serverPort string

	ctx, r := servicerunner.New(ctx,
		WithHTTPServeMux(
			"test",
			WithK8SLivenessProbe(func() error { return nil }),
			OnMuxInit(saveServerPort(&serverPort)),
		),
		OnRunning(func(ctx context.Context) (err error) {
			defer stopRunner(ctx)

			response, _ := httpRequest(http.MethodGet, serverPort, "/health", nil)
			is.Equal(response.StatusCode, http.StatusNoContent)

			return
		}),
	)

	is.NoErr(r.Run(ctx, nil))
}

func TestK8SReadinessProbes(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)
	var serverPort string

	tsProbe := &probe{}
	rmqProbe := &probe{}

	probes := map[string]handlers.ServiceProber{
		"timescale": tsProbe,
		"rabbit":    rmqProbe,
	}

	ctx, r := servicerunner.New(ctx,
		WithHTTPServeMux(
			"test",
			OnMuxInit(saveServerPort(&serverPort)),
			WithK8SReadinessProbes(probes),
		),
	)

	err := r.Run(ctx, func(context.Context) error {
		defer stopRunner(ctx)

		response, _ := httpRequest(http.MethodGet, serverPort, "/readyz", nil)
		is.Equal(response.StatusCode, http.StatusNoContent)

		return nil
	})

	is.NoErr(err)
	is.Equal(tsProbe.count, 1)
	is.Equal(rmqProbe.count, 1)
}

func TestK8SReadinessProbesWithVerboseOutput(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)
	var serverPort string

	probes := map[string]handlers.ServiceProber{"timescale": &probe{}, "rabbit": &probe{}}

	ctx, r := servicerunner.New(ctx,
		WithHTTPServeMux(
			"test",
			OnMuxInit(saveServerPort(&serverPort)),
			WithK8SReadinessProbes(probes),
		),
	)

	err := r.Run(ctx, func(context.Context) error {
		defer stopRunner(ctx)

		response, body := httpRequest(http.MethodGet, serverPort, "/readyz?verbose", nil)
		is.Equal(response.StatusCode, http.StatusOK)
		is.Equal("[+]rabbit ok\n[+]timescale ok\nhealthz check passed\n", string(body))

		return nil
	})

	is.NoErr(err)
}

func TestK8SReadinessProbesWithVerboseOutputAndExcludedCheck(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)
	var serverPort string

	probes := map[string]handlers.ServiceProber{"timescale": &probe{}, "rabbit": &probe{}}

	ctx, r := servicerunner.New(ctx,
		WithHTTPServeMux(
			"test",
			OnMuxInit(saveServerPort(&serverPort)),
			WithK8SReadinessProbes(probes),
		),
	)

	err := r.Run(ctx, func(context.Context) error {
		defer stopRunner(ctx)

		response, body := httpRequest(http.MethodGet, serverPort, "/readyz?verbose&exclude=rabbit", nil)
		is.Equal(response.StatusCode, http.StatusOK)
		is.Equal("[+]rabbit excluded: ok\n[+]timescale ok\nhealthz check passed\n", string(body))

		return nil
	})

	is.NoErr(err)
}

func TestK8SReadinessProbesWithVerboseOutputAndSingleCheck(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)
	var serverPort string

	probes := map[string]handlers.ServiceProber{"timescale": &probe{}, "rabbit": &probe{}}

	ctx, r := servicerunner.New(ctx,
		WithHTTPServeMux(
			"test",
			OnMuxInit(saveServerPort(&serverPort)),
			WithK8SReadinessProbes(probes),
		),
	)

	err := r.Run(ctx, func(context.Context) error {
		defer stopRunner(ctx)

		response, body := httpRequest(http.MethodGet, serverPort, "/readyz/timescale?verbose", nil)
		is.Equal(response.StatusCode, http.StatusOK)
		is.Equal("[+]timescale ok\nhealthz check passed\n", string(body))

		return nil
	})

	is.NoErr(err)
}

func TestFailsIfMoreThanOneMuxSharesPort(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)

	ctx, r := servicerunner.New(ctx,
		OnRunning(stopRunner),
		WithHTTPServeMux("test1", servicerunner.WithPort("8000")),
		WithHTTPServeMux("test2", servicerunner.WithPort("8000")),
	)

	err := r.Run(ctx, nil)

	is.Equal(err.Error(), "failed to listen: listen tcp 0.0.0.0:8000: bind: address already in use")
}

func TestStopsIfWorkerSignalsAnError(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)
	expectedError := errors.New("thisiswronginsomanyways!!!")
	defer stopRunner(ctx)

	ctx, r := servicerunner.New(ctx)
	worker := func(context.Context) error {
		return expectedError
	}

	err := r.Run(ctx, worker)

	is.True(err != nil)
	is.Equal(expectedError.Error(), err.Error())
}

func TestCancelsWorkerContextIfParentContextIsCanceled(t *testing.T) {
	is, ctx, stopRunner := setupTest(t)

	ctx, r := servicerunner.New(ctx)
	worker := func(ctx context.Context) error {
		go stopRunner(ctx)
		<-ctx.Done()
		return nil
	}

	err := r.Run(ctx, worker)

	is.NoErr(err)
}

func TestStartingHookMustNotBlock(t *testing.T) {
	is, ctx, _ := setupTest(t)

	ctx, r := servicerunner.New(ctx,
		WithStartingTimeout(10*time.Millisecond),
		OnStarting(func(context.Context) error {
			time.Sleep(30 * time.Second)
			return nil
		}),
	)

	err := r.Run(ctx, nil)

	is.Equal(err.Error(), "hook did not return within the maximum allowed 10ms")
}

func saveServerPort(here *string) func(context.Context, string, string, *http.ServeMux) error {
	return func(_ context.Context, _ string, port string, _ *http.ServeMux) error {
		*here = port
		return nil
	}
}

func setupTest(t *testing.T) (*is.I, context.Context, func(context.Context) error) {
	const testTimeout time.Duration = (5 * time.Second)

	ctx, cancelFunc := context.WithTimeout(context.Background(), testTimeout)

	runnerStopper := func(context.Context) error {
		cancelFunc()
		return nil
	}

	return is.New(t), ctx, runnerStopper
}

func httpRequest(method, port, path string, body io.Reader) (*http.Response, string) {
	req, _ := http.NewRequest(method, "http://localhost:"+port+path, body)

	resp, _ := http.DefaultClient.Do(req)
	respBody, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	return resp, string(respBody)
}

type probe struct {
	count  int
	result error
}

func (p *probe) Probe(ctx context.Context) error {
	p.count++
	return p.result
}
