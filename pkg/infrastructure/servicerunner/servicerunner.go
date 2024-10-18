package servicerunner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/diwise/service-chassis/pkg/infrastructure/buildinfo"
	"github.com/diwise/service-chassis/pkg/infrastructure/net/http/handlers"
	"github.com/diwise/service-chassis/pkg/infrastructure/o11y"
)

type Runner interface {
	Run(ctx context.Context, worker func(context.Context) error) error
}

type muxCfg struct {
	name   string
	port   string
	listen string

	probesEnabled bool
	probers       map[string]handlers.ServiceProber
	isAlive       func() error

	initFunc func(ctx context.Context, identifier, port string, handler *http.ServeMux) error
}

type runnerCfg struct {
	name    string
	version string

	muxes []*muxCfg

	onInit        func(context.Context) error
	onInitTimeout time.Duration

	onStarting        func(context.Context) error
	onStartingTimeout time.Duration

	onRunning  func(context.Context) error
	onShutdown func(context.Context) error
}

type RunnerConfigFunc func(*runnerCfg)

func WithName(name string) RunnerConfigFunc {
	return func(cfg *runnerCfg) {
		cfg.name = name
	}
}

func WithNameAndVersion(name, version string) RunnerConfigFunc {
	return func(cfg *runnerCfg) {
		WithName(name)(cfg)
		cfg.version = version
	}
}

func WithStartingTimeout(timeout time.Duration) RunnerConfigFunc {
	return func(cfg *runnerCfg) {
		cfg.onStartingTimeout = timeout
	}
}

func OnInit(initFunc func(context.Context) error) RunnerConfigFunc {
	return func(cfg *runnerCfg) {
		cfg.onInit = initFunc
	}
}

func OnRunning(runningFunc func(context.Context) error) RunnerConfigFunc {
	return func(cfg *runnerCfg) {
		cfg.onRunning = runningFunc
	}
}

func OnStarting(startupFunc func(context.Context) error) RunnerConfigFunc {
	return func(cfg *runnerCfg) {
		cfg.onStarting = startupFunc
	}
}

func OnShutdown(shutdownFunc func(context.Context) error) RunnerConfigFunc {
	return func(cfg *runnerCfg) {
		cfg.onShutdown = shutdownFunc
	}
}

type MuxConfigFunc func(*muxCfg)

func WithListenAddr(listen string) MuxConfigFunc {
	return func(cfg *muxCfg) {
		cfg.listen = listen
	}
}

func WithPort(port string) MuxConfigFunc {
	return func(cfg *muxCfg) {
		cfg.port = port
	}
}

func WithK8SLivenessProbe(isAlive func() error) MuxConfigFunc {
	return func(cfg *muxCfg) {
		cfg.probesEnabled = true
		cfg.isAlive = isAlive
	}
}

func WithK8SReadinessProbes(probers map[string]handlers.ServiceProber) MuxConfigFunc {
	return func(cfg *muxCfg) {
		cfg.probesEnabled = true
		cfg.probers = map[string]handlers.ServiceProber{}

		for name, prober := range probers {
			cfg.probers[strings.ToLower(name)] = prober
		}
	}
}

func OnMuxInit(initFunc func(ctx context.Context, identifier, port string, handler *http.ServeMux) error) MuxConfigFunc {
	return func(cfg *muxCfg) {
		cfg.initFunc = initFunc
	}
}

func WithHTTPServeMux(identifer string, opts ...MuxConfigFunc) RunnerConfigFunc {
	return func(cfg *runnerCfg) {
		mcfg := &muxCfg{
			name:          identifer,
			listen:        "0.0.0.0",
			port:          "0",
			probesEnabled: false,
			isAlive:       func() error { return nil },
			initFunc:      func(ctx context.Context, identifier, port string, handler *http.ServeMux) error { return nil },
		}

		for _, option := range opts {
			option(mcfg)
		}

		cfg.muxes = append(cfg.muxes, mcfg)
	}
}

type httpSrvr struct {
	listener net.Listener
	mux      *http.ServeMux
	server   *http.Server
}

type runner struct {
	cfg *runnerCfg

	httpServers []*httpSrvr

	configError error
	o11yCleanup o11y.CleanupFunc
}

func doHook(ctx context.Context, hook func(context.Context) error, timeout time.Duration) (err error) {
	hookResult := make(chan error)
	hookContext, hookDone := context.WithTimeout(ctx, timeout)

	go func() {
		defer hookDone()
		hookResult <- hook(hookContext)
	}()

	select {
	case <-hookContext.Done():
		if errors.Is(context.Cause(hookContext), context.DeadlineExceeded) {
			err = fmt.Errorf("hook did not return within the maximum allowed %s", timeout.String())
		}
	case err = <-hookResult:
	}

	return
}

// Run implements Runner.
func (r *runner) Run(ctx context.Context, worker func(context.Context) error) (err error) {
	defer r.o11yCleanup()

	if r.configError != nil {
		return r.configError
	}

	err = doHook(ctx, r.cfg.onStarting, r.cfg.onStartingTimeout)
	if err != nil {
		return
	}

	errChan := make(chan error, len(r.httpServers)+1)
	defer close(errChan)

	var wg sync.WaitGroup

	for serverIndex := range r.httpServers {
		wg.Add(1)

		go func(s *httpSrvr, errc chan<- error) {
			defer wg.Done()

			if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
				errc <- fmt.Errorf(
					"failed to start request router on address %s: %s", s.server.Addr, err.Error(),
				)
			}
		}(r.httpServers[serverIndex], errChan)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer close(sigChan)

	err = doHook(ctx, r.cfg.onRunning, 30*time.Second)
	if err != nil {
		return
	}

	if worker != nil && context.Cause(ctx) == nil {
		wg.Add(1)

		go func() {
			defer wg.Done()

			workerError := worker(ctx)
			if workerError != nil {
				errChan <- workerError
			}
		}()
	}

	select {
	case err = <-errChan:
	case <-ctx.Done():
	case <-sigChan:
	}

	err = errors.Join(
		err,
		doHook(context.WithoutCancel(ctx), r.cfg.onShutdown, 30*time.Second),
	)

	for serverIndex := range r.httpServers {
		e := r.httpServers[serverIndex].server.Shutdown(ctx)
		if e != nil {
			err = errors.Join(err, fmt.Errorf("failed to shutdown web server: %s", err.Error()))
		}
	}

	theWaitIsOver := make(chan struct{})
	go func() {
		defer close(theWaitIsOver)
		wg.Wait()
	}()

	select {
	case <-theWaitIsOver:
	case <-time.After(10 * time.Second):
		err = fmt.Errorf("timed out waiting for shutdown")
	}

	return
}

func New(ctx context.Context, opts ...RunnerConfigFunc) (context.Context, Runner) {

	noop := func(context.Context) error { return nil }

	cfg := &runnerCfg{
		name:              "anonymous",
		version:           buildinfo.SourceVersion(),
		muxes:             make([]*muxCfg, 0, 2),
		onInit:            noop,
		onInitTimeout:     30 * time.Second,
		onStarting:        noop,
		onStartingTimeout: 30 * time.Second,
		onRunning:         noop,
		onShutdown:        noop,
	}

	for _, option := range opts {
		option(cfg)
	}

	r := &runner{
		cfg:         cfg,
		httpServers: make([]*httpSrvr, 0, len(cfg.muxes)),
	}

	ctx, _, r.o11yCleanup = o11y.Init(ctx, r.cfg.name, r.cfg.version)

	r.configError = doHook(ctx, r.cfg.onInit, r.cfg.onInitTimeout)

	for _, muxConf := range r.cfg.muxes {
		mux := http.NewServeMux()

		if muxConf.probesEnabled {
			nhh := handlers.NewHealthHandler(ctx, muxConf.probers)
			mux.HandleFunc("GET /health", nhh)
			mux.HandleFunc("GET /healthz", nhh)

			mux.HandleFunc("GET /livez", handlers.NewLivenessHandler(ctx, muxConf.isAlive))
			mux.HandleFunc("GET /readyz", handlers.NewReadinessHandler(ctx, muxConf.probers))
			mux.HandleFunc("GET /readyz/{check}", handlers.NewSingleReadinessHandler(ctx, muxConf.probers))
		}

		addr := muxConf.listen + ":" + muxConf.port
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			r.configError = fmt.Errorf("failed to listen: %s", err.Error())
			return ctx, r
		}

		_, port, _ := net.SplitHostPort(listener.Addr().String())

		err = muxConf.initFunc(ctx, muxConf.name, port, mux)
		if err != nil {
			r.configError = fmt.Errorf("failed to init servemux: %s", err.Error())
			listener.Close()
			return ctx, r
		}

		r.httpServers = append(r.httpServers, &httpSrvr{
			listener: listener,
			mux:      mux,
			server:   &http.Server{Addr: addr, Handler: mux},
		})
	}

	return ctx, r
}
