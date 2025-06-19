package router

import (
	"net/http"
	"slices"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type Router interface {
	Route(route string, r func(Router))

	Use(middlewares ...func(http.Handler) http.Handler)

	Connect(pattern string, h http.HandlerFunc)
	Delete(pattern string, h http.HandlerFunc)
	Get(pattern string, h http.HandlerFunc)
	Head(pattern string, h http.HandlerFunc)
	Options(pattern string, h http.HandlerFunc)
	Patch(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
	Put(pattern string, h http.HandlerFunc)
	Trace(pattern string, h http.HandlerFunc)
}

type opt struct {
	tagRoutes bool
}

func WithTaggedRoutes() func(*opt) {
	return func(o *opt) {
		o.tagRoutes = true
	}
}

func New(mux *http.ServeMux, options ...func(*opt)) Router {
	o := &opt{}

	for _, applyOption := range options {
		applyOption(o)
	}

	return &impl{
		mux:         mux,
		middlewares: make([]func(http.Handler) http.Handler, 0, 16),
		tagRoutes:   o.tagRoutes,
	}
}

type impl struct {
	prefix      string
	mux         *http.ServeMux
	middlewares []func(http.Handler) http.Handler
	tagRoutes   bool
}

func (i *impl) register(method, pattern string, h http.Handler) {
	if i.tagRoutes {
		h = otelhttp.WithRouteTag(pattern, h)
	}
	i.mux.Handle(method+" "+i.prefix+pattern, i.wrap(h))
}

func (i *impl) wrap(h http.Handler) http.Handler {
	handler := h
	for _, mw := range slices.Backward(i.middlewares) {
		handler = mw(handler)
	}
	return handler
}

// Connect implements Router.
func (i *impl) Connect(pattern string, h http.HandlerFunc) {
	i.register(http.MethodConnect, pattern, h)
}

// Delete implements Router.
func (i *impl) Delete(pattern string, h http.HandlerFunc) {
	i.register(http.MethodDelete, pattern, h)
}

// Get implements Router.
func (i *impl) Get(pattern string, h http.HandlerFunc) {
	i.register(http.MethodGet, pattern, h)
}

// Head implements Router.
func (i *impl) Head(pattern string, h http.HandlerFunc) {
	i.register(http.MethodHead, pattern, h)
}

// Options implements Router.
func (i *impl) Options(pattern string, h http.HandlerFunc) {
	i.register(http.MethodOptions, pattern, h)
}

// Patch implements Router.
func (i *impl) Patch(pattern string, h http.HandlerFunc) {
	i.register(http.MethodPatch, pattern, h)
}

// Post implements Router.
func (i *impl) Post(pattern string, h http.HandlerFunc) {
	i.register(http.MethodPost, pattern, h)
}

// Put implements Router.
func (i *impl) Put(pattern string, h http.HandlerFunc) {
	i.register(http.MethodPut, pattern, h)
}

// Route implements Router.
func (i *impl) Route(route string, r func(Router)) {
	copy := *i
	copy.prefix = copy.prefix + route
	r(&copy)
}

// Trace implements Router.
func (i *impl) Trace(pattern string, h http.HandlerFunc) {
	i.register(http.MethodTrace, pattern, h)
}

// Use implements Router.
func (i *impl) Use(middlewares ...func(http.Handler) http.Handler) {
	i.middlewares = append(i.middlewares, middlewares...)
}
