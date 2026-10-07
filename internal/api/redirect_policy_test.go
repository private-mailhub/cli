package api

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRedirectPolicy_DefaultPortsShareOrigin(t *testing.T) {
	testCases := []struct {
		name   string
		source string
		target string
	}{
		{
			name:   "HTTPS omitted to explicit port 443",
			source: "https://mailhub.example/api/auth/cli/device/token",
			target: "https://mailhub.example:443/api/auth/cli/device/token",
		},
		{
			name:   "HTTPS explicit port 443 to omitted",
			source: "https://mailhub.example:443/api/auth/cli/device/token",
			target: "https://mailhub.example/api/auth/cli/device/token",
		},
		{
			name:   "HTTP omitted to explicit port 80",
			source: "http://mailhub.example/api/auth/cli/device/token",
			target: "http://mailhub.example:80/api/auth/cli/device/token",
		},
		{
			name:   "HTTP explicit port 80 to omitted",
			source: "http://mailhub.example:80/api/auth/cli/device/token",
			target: "http://mailhub.example/api/auth/cli/device/token",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sourceURL, err := url.Parse(testCase.source)
			if err != nil {
				t.Fatal("parse source URL")
			}
			targetURL, err := url.Parse(testCase.target)
			if err != nil {
				t.Fatal("parse target URL")
			}

			previous := &http.Request{
				Method: http.MethodPost,
				URL:    sourceURL,
				Header: http.Header{"Authorization": []string{"Bearer test-credential"}},
			}
			request := &http.Request{
				Method: http.MethodPost,
				URL:    targetURL,
				Header: make(http.Header),
				Body:   io.NopCloser(strings.NewReader("placeholder body")),
			}

			if err := redirectPolicy(request, []*http.Request{previous}); err != nil {
				t.Fatalf("same-origin POST redirect was rejected for case %q", testCase.name)
			}
			if request.Header.Get("Authorization") == "" {
				t.Fatalf("same-origin redirect did not preserve authorization for case %q", testCase.name)
			}
		})
	}
}
