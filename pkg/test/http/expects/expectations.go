package expects

import (
	"io"
	"net/http"

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
