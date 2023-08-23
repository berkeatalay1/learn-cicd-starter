package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeyErrNoAuthHeaderIncluded(T *testing.T) {
	header := http.Header{
		"Host":         {"www.host.com"},
		"Content-Type": {"application/json"},
	}

	apiKey, err := GetAPIKey(header)
	if err != ErrNoAuthHeaderIncluded {
		T.Fatalf(`Error = %v, %v, want %v, error`, apiKey, err, ErrNoAuthHeaderIncluded)
	}
}

func TestGetAPIKeyCheckMalformed(T *testing.T) {
	header := http.Header{
		"Host":          {"www.host.com"},
		"Content-Type":  {"application/json"},
		"Authorization": {"application/json"},
	}

	apiKey, err := GetAPIKey(header)
	if err.Error() != "malformed authorization header" {
		T.Fatalf(`Error = %v, %v, want %v, error`, apiKey, err, "malformed authorization header")
	}
}

func TestGetAPIKeyCheckCorrect(T *testing.T) {
	header := http.Header{
		"Host":          {"www.host.com"},
		"Content-Type":  {"application/json"},
		"Authorization": {"ApiKey 123"},
	}

	apiKey, err := GetAPIKey(header)
	if err != nil || apiKey != "123" {
		T.Fatalf(`Error = %v, %v, want %v, error`, apiKey, err, 123)
	}
}
