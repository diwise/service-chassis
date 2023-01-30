package expects

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/matryer/is"
)

func AnyInput() func(*is.I, *http.Request) {
	return func(*is.I, *http.Request) {}
}

func RequestBody(body string) func(*is.I, *http.Request) {
	return func(is *is.I, r *http.Request) {
		reqBytes, err := io.ReadAll(r.Body)
		is.NoErr(err)

		reqString := string(reqBytes)
		is.Equal(reqString, body)
	}
}

func RequestBodyContaining(substrings ...string) func(*is.I, *http.Request) {
	return func(is *is.I, r *http.Request) {
		reqBytes, err := io.ReadAll(r.Body)
		is.NoErr(err)

		reqString := string(reqBytes)

		for _, subs := range substrings {
			if !strings.Contains(reqString, subs) {
				is.Equal("expectation", fmt.Sprintf("request body does not contain %s", subs))
			}
		}
	}
}

func RequestMethod(method string) func(*is.I, *http.Request) {
	return func(is *is.I, r *http.Request) {
		is.Equal(r.Method, method)
	}
}

func RequestPath(path string) func(*is.I, *http.Request) {
	return func(is *is.I, r *http.Request) {
		is.Equal(r.URL.Path, path)
	}
}

func QueryParamContains(name, value string) func(*is.I, *http.Request) {
	return func(is *is.I, r *http.Request) {
		is.True(r.URL.Query().Has(name)) // query param should exist

		for _, v := range strings.Split(r.URL.Query().Get(name), ",") {
			if v == value {
				return // it is a match!
			}
		}

		is.Fail() // query params did not contain expected value
	}
}

func QueryParamEquals(name, value string) func(*is.I, *http.Request) {
	return func(is *is.I, r *http.Request) {
		is.True(r.URL.Query().Has(name))         // query param should exist
		is.Equal(r.URL.Query().Get(name), value) // query param should match
	}
}
