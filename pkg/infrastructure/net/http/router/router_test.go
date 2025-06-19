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

	r.Route("/api", func(r router.Router) {
		r.Route("/test", func(r router.Router) {
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

	r.Route("/api", func(r router.Router) {
		r.Route("/test", func(r router.Router) {
			r.Route("/bananas", func(r router.Router) {
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
