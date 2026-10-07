package cli_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/private-mailhub/mailhub-cli/internal/cli"
	"github.com/private-mailhub/mailhub-cli/internal/credentials"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.Execute(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestCommand_기본명령(t *testing.T) {
	t.Run("unknown command, flag, version extra arg는 모두 사용법 오류다", func(t *testing.T) {
		for _, args := range [][]string{{"wat"}, {"version", "--wat"}, {"version", "extra"}} {
			code, _, stderr := run(t, args...)
			if code != 2 || stderr == "" {
				t.Errorf("args=%v code=%d stderr=%q", args, code, stderr)
			}
		}
	})
	t.Run("version은 stdout에 버전을 출력하고 stderr는 비운다", func(t *testing.T) {
		code, stdout, stderr := run(t, "version")
		if code != 0 || stdout != "mailhub 0.1.2\n" || stderr != "" {
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

func TestCommand_KeyRevokeValidation(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("MAILHUB_API_URL", server.URL)
	t.Setenv("MAILHUB_TOKEN", "mhk_1_secret")
	for _, id := range []string{"abc", "0"} {
		code, _, _ := run(t, "auth", "keys", "revoke", id)
		if code != 2 {
			t.Errorf("id=%s code=%d", id, code)
		}
	}
	if requests != 0 {
		t.Fatalf("invalid revoke made %d requests", requests)
	}
}

func TestCommand_KeyRevokeDoesNotFallbackToCurrent(t *testing.T) {
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/api/api-keys/1" {
			http.Error(w, `{"result":"fail","error":"not_found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, "unexpected fallback", http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("MAILHUB_API_URL", server.URL)
	t.Setenv("MAILHUB_TOKEN", "mhk_1_secret")
	code, _, _ := run(t, "auth", "keys", "revoke", "1")
	if code != 1 || strings.Contains(strings.Join(paths, ","), "/current") {
		t.Fatalf("code=%d paths=%v", code, paths)
	}
}

func TestCommand_환경변수인증메타데이터(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("MAILHUB_CONFIG_DIR", configDir)
	if err := credentials.SaveConfig(credentials.Config{KeyID: "1", ExpiresAt: "2030-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAILHUB_TOKEN", "mhk_env_secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/api-keys/current" || r.URL.Path == "/api/api-keys/1" {
			_, _ = io.WriteString(w, `{"result":"success","data":null}`)
			return
		}
		if r.URL.Path == "/api/api-keys" {
			_, _ = io.WriteString(w, `{"result":"success","data":[{"id":"1","expiresAt":"2030-01-01T00:00:00Z"}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	t.Setenv("MAILHUB_API_URL", server.URL)

	t.Run("logout은 원래 config를 보존하고 환경변수 제거 안내만 stderr에 남긴다", func(t *testing.T) {
		code, _, stderr := run(t, "auth", "logout")
		if code != 0 || !strings.Contains(stderr, "MAILHUB_TOKEN") || strings.Contains(stderr, "mhk_env_secret") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
		got, err := credentials.LoadConfig()
		if err != nil || got.KeyID != "1" {
			t.Fatalf("config=%+v err=%v", got, err)
		}
	})
	t.Run("keys revoke도 환경변수 토큰이면 같은 key id의 config를 보존한다", func(t *testing.T) {
		code, _, _ := run(t, "auth", "keys", "revoke", "1")
		if code != 0 {
			t.Fatalf("code=%d", code)
		}
		got, err := credentials.LoadConfig()
		if err != nil || got.KeyID != "1" {
			t.Fatalf("config=%+v err=%v", got, err)
		}
	})
	t.Run("status는 stale config의 key id 대신 환경변수 인증을 보고한다", func(t *testing.T) {
		code, stdout, _ := run(t, "auth", "status")
		if code != 0 || !strings.Contains(stdout, "MAILHUB_TOKEN") || strings.Contains(stdout, "Key ID: 1") {
			t.Fatalf("code=%d stdout=%q", code, stdout)
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

func TestCommand_AliasNullDescription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"result":"success","data":[{"id":"7","relayEmail":"exact@example.com","isActive":true,"description":null,"forwardCount":"0","createdAt":"2026-01-01T00:00:00Z","updatedAt":null}]}`)
	}))
	defer server.Close()
	t.Setenv("MAILHUB_API_URL", server.URL)
	t.Setenv("MAILHUB_TOKEN", "mhk_test_secret")
	code, stdout, stderr := run(t, "alias", "list", "--json")
	if code != 0 || !strings.Contains(stdout, `"description":null`) || strings.Contains(stderr, "<nil>") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
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
