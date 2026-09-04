package cli_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/private-mailhub/mailhub-cli/internal/cli"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.Execute(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestCommand_기본명령(t *testing.T) {
	t.Run("version은 stdout에 버전을 출력하고 stderr는 비운다", func(t *testing.T) {
		code, stdout, stderr := run(t, "version")
		if code != 0 || !strings.Contains(stdout, "0.1.0") || stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})

	t.Run("지원하지 않는 completion shell은 인자 오류로 종료한다", func(t *testing.T) {
		code, _, stderr := run(t, "completion", "powershell")
		if code != 2 || stderr == "" {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})

	t.Run("인증이 필요한 명령은 토큰이 없으면 종료 코드 3을 반환한다", func(t *testing.T) {
		t.Setenv("MAILHUB_TOKEN", "")
		code, _, stderr := run(t, "alias", "list")
		if code != 3 || !strings.Contains(stderr, "auth") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})

	t.Run("label과 clear를 함께 지정하면 종료 코드 2를 반환한다", func(t *testing.T) {
		code, _, stderr := run(t, "alias", "label", "7", "업무", "--clear")
		if code != 2 || stderr == "" {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})
}

func TestCommand_AliasAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/relay-emails" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"result":"success","data":[{"id":"7","relayEmail":"exact@example.com","isActive":true,"description":"업무","forwardCount":"2","createdAt":"2026-01-01T00:00:00Z","updatedAt":null}]}`)
	}))
	defer server.Close()
	t.Setenv("MAILHUB_API_URL", server.URL)
	t.Setenv("MAILHUB_TOKEN", "mhk_test_secret")

	t.Run("list json은 stdout에만 JSON을 출력한다", func(t *testing.T) {
		code, stdout, stderr := run(t, "alias", "list", "--json")
		if code != 0 || !strings.Contains(stdout, `"relayEmail":"exact@example.com"`) || stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if strings.Contains(stdout+stderr, "mhk_test_secret") {
			t.Fatal("token leaked")
		}
	})

	t.Run("존재하지 않는 이메일은 정확히 일치하지 않으면 인자 오류다", func(t *testing.T) {
		code, _, stderr := run(t, "alias", "on", "EXACT@example.com")
		if code != 2 || stderr == "" {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})
}

func TestCommand_Logout(t *testing.T) {
	t.Run("환경변수 토큰 logout은 keychain 삭제를 시도하지 않는다", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || r.URL.Path != "/api/api-keys/current" {
				t.Fatalf("request=%s %s", r.Method, r.URL.Path)
			}
			_, _ = io.WriteString(w, `{"result":"success","data":null}`)
		}))
		defer server.Close()
		t.Setenv("MAILHUB_API_URL", server.URL)
		t.Setenv("MAILHUB_TOKEN", "mhk_env_secret")
		code, _, stderr := run(t, "auth", "logout")
		if code != 0 || strings.Contains(stderr, "keychain") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
		if strings.Contains(stderr, "mhk_env_secret") {
			t.Fatal("token leaked")
		}
	})
}
