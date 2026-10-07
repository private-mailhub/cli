package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogin_기본브라우저실행전에승인정보를출력한다(t *testing.T) {
	const (
		deviceCode = "device-secret"
		userCode   = "ABCD-EFGH"
	)
	var pollRequests int
	var verificationURI string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/api/auth/cli/device":
			_, _ = io.WriteString(w, `{"result":"success","data":{"deviceCode":"`+deviceCode+`","userCode":"`+userCode+`","verificationUri":"`+verificationURI+`","expiresIn":60,"interval":1}}`)
		case "/api/auth/cli/device/token":
			pollRequests++
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"result":"fail","error":"access_denied"}`)
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	verificationURI = server.URL + "/cli/authorize"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var openedURL string
	var outputAtOpen string
	application := &app{
		out:    &stdout,
		errOut: &stderr,
		openBrowser: func(rawURL string) error {
			openedURL = rawURL
			outputAtOpen = stdout.String()
			return nil
		},
	}
	root := application.rootCommand()
	root.SetArgs([]string{
		"--api-url",
		server.URL,
		"auth",
		"login",
		"--device-name",
		"Work Mac",
	})

	// When
	err := root.Execute()

	// Then
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("expected access_denied after the browser opened, got err=%v", err)
	}
	if openedURL != verificationURI {
		t.Fatalf("opened URL=%q, want %q", openedURL, verificationURI)
	}
	if !strings.Contains(outputAtOpen, verificationURI) || !strings.Contains(outputAtOpen, userCode) {
		t.Fatalf("approval instructions were not printed before browser open: %q", outputAtOpen)
	}
	if pollRequests != 1 {
		t.Fatalf("poll requests=%d, want 1", pollRequests)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty", stderr.String())
	}
}

func TestLogin_HelpDescribesNoBrowserBehavior(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := &app{out: &stdout, errOut: &stderr}
	root := application.rootCommand()
	root.SetArgs([]string{"auth", "login", "--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("show login help: %v", err)
	}

	var noBrowserDescription string
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.Contains(line, "--no-browser") {
			noBrowserDescription = strings.ToLower(line)
			break
		}
	}
	blocksBrowser := strings.Contains(noBrowserDescription, "browser") &&
		(strings.Contains(noBrowserDescription, "suppress") ||
			strings.Contains(noBrowserDescription, "do not open") ||
			strings.Contains(noBrowserDescription, "do not launch"))
	keepsInstructions := strings.Contains(noBrowserDescription, "instruction") &&
		strings.Contains(noBrowserDescription, "still") &&
		strings.Contains(noBrowserDescription, "print")
	if !blocksBrowser || !keepsInstructions {
		t.Fatalf("--no-browser help should explain that it suppresses browser launch while instructions still print; line=%q full help=%q", noBrowserDescription, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty", stderr.String())
	}
}
