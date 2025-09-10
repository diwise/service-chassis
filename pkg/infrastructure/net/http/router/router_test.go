package router_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/diwise/service-chassis/pkg/infrastructure/net/http/router"
	"github.com/matryer/is"
)

func TestRegisterRoutes(t *testing.T) {
	is := is.New(t)

	mux := http.NewServeMux()
	r := router.New(mux)

	r.Route("/api", func(r router.ServeMux) {
		r.Route("/test", func(r router.ServeMux) {
			r.Get("/bananas", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/test/bananas")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
}

func TestRegisterRouteWithPathValue(t *testing.T) {
	is := is.New(t)

	mux := http.NewServeMux()
	r := router.New(mux)

	bananaID := ""

	r.Route("/api", func(r router.ServeMux) {
		r.Route("/test", func(r router.ServeMux) {
			r.Route("/bananas", func(r router.ServeMux) {
				r.Get("/{id}", func(w http.ResponseWriter, r *http.Request) {
					bananaID = r.PathValue("id")
					w.WriteHeader(http.StatusOK)
				})
			})
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/test/bananas/42")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
	is.Equal(bananaID, "42")
}

func TestRegisterGroupedRoutes(t *testing.T) {
	is := is.New(t)

	mux := http.NewServeMux()
	r := router.New(mux)

	r.Route("/api", func(r router.ServeMux) {
		r.Route("/v1", func(r router.ServeMux) {
			r.Group(func(r router.ServeMux) {
				r.Route("/test", func(r router.ServeMux) {
					r.Get("/oranges", func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
					})
				})
			})
		})
		r.Route("/v2", func(r router.ServeMux) {
			r.Group(func(r router.ServeMux) {
				r.Route("/test", func(r router.ServeMux) {
					r.Get("/oranges", func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
					})
				})
			})
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v2/test/oranges")
	is.NoErr(err)
	is.Equal(resp.StatusCode, http.StatusOK)
}

func TestMultipleMethodsOnSameRoute(t *testing.T) {
	is := is.New(t)

	mux := http.NewServeMux()
	r := router.New(mux)

	getCalls := 0
	headCalls := 0

	r.Route("/api", func(r router.ServeMux) {
		r.Route("/test", func(r router.ServeMux) {
			r.Get("", func(w http.ResponseWriter, r *http.Request) {
				getCalls++
				w.WriteHeader(http.StatusOK)
			})
			r.Head("", func(w http.ResponseWriter, r *http.Request) {
				headCalls++
				w.WriteHeader(http.StatusOK)
			})
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/test")
	is.Equal(resp.StatusCode, http.StatusOK)

	resp, _ = http.Head(ts.URL + "/api/test")
	is.Equal(resp.StatusCode, http.StatusOK)

	is.Equal(getCalls, 1)
	is.Equal(headCalls, 1)
}

func TestAddsSlashesAutomatically(t *testing.T) {
	is := is.New(t)

	mux := http.NewServeMux()
	r := router.New(mux)

	r.Route("a", func(r router.ServeMux) {
		r.Route("b", func(r router.ServeMux) {
			r.Get("c", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/a/b/c")
	is.Equal(resp.StatusCode, http.StatusOK)
}
