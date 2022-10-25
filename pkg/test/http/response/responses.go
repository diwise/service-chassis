package response

import "net/http"

func ContentType(contentType string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Add("Content-Type", contentType)
	}
}

func Location(loc string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Add("Location", loc)
	}
}

func Body(body []byte) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Write(body)
	}
}

func Code(code int) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
	}
}
