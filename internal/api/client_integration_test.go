package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/private-mailhub/mailhub-cli/internal/api"
)

func TestClient_요청계약(t *testing.T) {
	t.Run("교차 origin redirect에서는 Authorization을 전달하지 않는다", func(t *testing.T) {
		var leaked string
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			leaked = r.Header.Get("Authorization")
			_, _ = io.WriteString(w, `{"result":"success","data":[]}`)
		}))
		defer target.Close()
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, target.URL+"/api/relay-emails", http.StatusFound)
		}))
		defer source.Close()
		if _, err := api.NewClient(source.URL, "mhk_secret", "0.1.0").ListAliases(t.Context()); err != nil {
			t.Fatal(err)
		}
		if leaked != "" {
			t.Fatalf("cross-origin token leaked: %q", leaked)
		}
	})

	t.Run("성공 응답은 공통 envelope를 해석하고 인증 헤더와 User-Agent를 보낸다", func(t *testing.T) {
		var gotAuth, gotUA string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotUA = r.Header.Get("Authorization"), r.Header.Get("User-Agent")
			if r.Method != http.MethodGet || r.URL.Path != "/api/relay-emails" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			_, _ = io.WriteString(w, `{"result":"success","data":[{"id":"7","relayEmail":"a@example.com","isActive":true,"description":"","forwardCount":"0","createdAt":"2026-01-01T00:00:00Z","updatedAt":null}]}`)
		}))
		defer server.Close()

		client := api.NewClient(server.URL, "mhk_secret", "0.1.0")
		aliases, err := client.ListAliases(t.Context())
		if err != nil || len(aliases) != 1 || aliases[0].ID != "7" || aliases[0].RelayEmail != "a@example.com" || !aliases[0].IsActive {
			t.Fatalf("aliases=%+v err=%v", aliases, err)
		}
		if gotAuth != "Bearer mhk_secret" || gotUA != "mailhub-cli/0.1.0" {
			t.Fatalf("headers auth=%q ua=%q", gotAuth, gotUA)
		}
	})

	t.Run("실패 envelope는 안정적인 오류 코드를 보존한다", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"result":"fail","error":"API_KEY_EXPIRED","data":null}`)
		}))
		defer server.Close()
		_, err := api.NewClient(server.URL, "expired", "0.1.0").ListAliases(t.Context())
		if err == nil || !strings.Contains(err.Error(), "API_KEY_EXPIRED") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("JSON 요청은 description을 그대로 전송한다", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/api/relay-emails/create" {
				t.Fatalf("request=%s %s", r.Method, r.URL.Path)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["description"] != "업무용" {
				t.Fatalf("body=%v err=%v", body, err)
			}
			_, _ = io.WriteString(w, `{"result":"success","data":{"id":"8","relayEmail":"b@example.com","isActive":true,"description":"업무용","forwardCount":"0","createdAt":"2026-01-01T00:00:00Z","updatedAt":null}}`)
		}))
		defer server.Close()
		alias, err := api.NewClient(server.URL, "token", "0.1.0").CreateAlias(t.Context(), "업무용")
		if err != nil || alias.ID != "8" || alias.RelayEmail != "b@example.com" || alias.Description != "업무용" {
			t.Fatalf("alias=%+v err=%v", alias, err)
		}
	})
	t.Run("생성 응답 description null은 nil 포인터로 보존한다", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"result":"success","data":{"id":"8","relayEmail":"b@example.com","isActive":true,"description":null,"createdAt":"2026-01-01T00:00:00Z"}}`)
		}))
		defer server.Close()
		alias, err := api.NewClient(server.URL, "token", "0.1.0").CreateAlias(t.Context(), "")
		if err != nil || alias.Description != nil {
			t.Fatalf("alias=%+v err=%v", alias, err)
		}
	})
}

func TestVerificationURL_보안검증(t *testing.T) {
	t.Run("API localhost와 별도 HTTPS web host 포트를 허용한다", func(t *testing.T) {
		if err := api.ValidateVerificationURL("https://web.example:5173/cli/authorize"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("loopback 이외 HTTP와 userinfo URL은 거부한다", func(t *testing.T) {
		for _, raw := range []string{"http://web.example/cli/authorize", "https://user:pass@web.example/cli/authorize"} {
			if err := api.ValidateVerificationURL(raw); err == nil {
				t.Errorf("accepted unsafe URL: %s", raw)
			}
		}
	})
}

func TestClient_DeviceAuthorization(t *testing.T) {
	t.Run("HTTP 요청 timeout은 전체 device deadline과 구분되는 context 오류를 반환한다", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(50 * time.Millisecond) }))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
		defer cancel()
		_, err := api.NewClient(server.URL, "", "0.1.0").StartDeviceAuthorization(ctx, "Mac")
		if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("첫 polling 전에 interval만큼 기다리고 deadline이면 요청하지 않는다", func(t *testing.T) {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			_, _ = io.WriteString(w, `{"result":"fail","error":"authorization_pending"}`)
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()
		_, err := api.NewClient(server.URL, "", "0.1.0").PollDeviceToken(ctx, "dc", 100*time.Millisecond)
		if err == nil || calls != 0 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})

	t.Run("pending과 slow_down을 거쳐 승인 키를 반환한다", func(t *testing.T) {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.URL.Path == "/api/auth/cli/device" {
				_, _ = io.WriteString(w, `{"result":"success","data":{"deviceCode":"dc","userCode":"UC","verificationUri":"https://private-mailhub.com/cli/authorize","expiresIn":600,"interval":0}}`)
				return
			}
			if calls == 2 {
				_, _ = io.WriteString(w, `{"result":"fail","error":"authorization_pending"}`)
				return
			}
			if calls == 3 {
				_, _ = io.WriteString(w, `{"result":"fail","error":"slow_down"}`)
				return
			}
			_, _ = io.WriteString(w, `{"result":"success","data":{"apiKey":"mhk_raw","keyId":"k1","expiresAt":"2030-01-01T00:00:00Z","scopes":["relay:read"]}}`)
		}))
		defer server.Close()
		start, err := api.NewClient(server.URL, "", "0.1.0").StartDeviceAuthorization(t.Context(), "Mac")
		if err != nil || start.DeviceCode != "dc" {
			t.Fatalf("start=%+v err=%v", start, err)
		}
		result, err := api.NewClient(server.URL, "", "0.1.0").PollDeviceToken(t.Context(), "dc", time.Millisecond)
		if err != nil || result.APIKey != "mhk_raw" || result.KeyID != "k1" {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})

	t.Run("거부와 만료는 인증 오류로 구분된다", func(t *testing.T) {
		for _, code := range []string{"access_denied", "expired_token"} {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, `{"result":"fail","error":"`+code+`"}`)
			}))
			_, err := api.NewClient(server.URL, "", "0.1.0").PollDeviceToken(t.Context(), "dc", time.Millisecond)
			server.Close()
			if err == nil || !strings.Contains(err.Error(), code) {
				t.Errorf("code=%s err=%v", code, err)
			}
		}
	})
}

func TestClient_키와별칭(t *testing.T) {
	t.Run("키 목록과 키 폐기는 계약된 endpoint를 사용한다", func(t *testing.T) {
		var paths []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.Method+" "+r.URL.Path)
			if r.Method == http.MethodGet {
				_, _ = io.WriteString(w, `{"result":"success","data":[{"id":"1","expiresAt":"2030-01-01T00:00:00Z","revokedAt":null,"scopes":["relay:read"]}]}`)
				return
			}
			_, _ = io.WriteString(w, `{"result":"success","data":null}`)
		}))
		defer server.Close()
		client := api.NewClient(server.URL, "token", "0.1.0")
		keys, err := client.ListKeys(t.Context())
		if err != nil || len(keys) != 1 || keys[0].ID != "1" {
			t.Fatalf("keys=%+v err=%v", keys, err)
		}
		if err := client.RevokeKey(t.Context(), "1"); err != nil {
			t.Fatal(err)
		}
		if strings.Join(paths, ",") != "GET /api/api-keys,DELETE /api/api-keys/1" {
			t.Fatalf("paths=%v", paths)
		}
	})

	t.Run("별칭 활성화와 설명 초기화는 PATCH body를 보낸다", func(t *testing.T) {
		var bodies []map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			bodies = append(bodies, body)
			_, _ = io.WriteString(w, `{"result":"success","data":null}`)
		}))
		defer server.Close()
		client := api.NewClient(server.URL, "token", "0.1.0")
		if err := client.SetAliasActive(t.Context(), "7", true); err != nil {
			t.Fatal(err)
		}
		if err := client.UpdateAliasDescription(t.Context(), "7", ""); err != nil {
			t.Fatal(err)
		}
		if bodies[0]["isActive"] != true || bodies[1]["description"] != "" {
			t.Fatalf("bodies=%v", bodies)
		}
	})
}
