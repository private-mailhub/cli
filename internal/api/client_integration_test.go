package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
		var pollCalls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/auth/cli/device" {
				_, _ = io.WriteString(w, `{"result":"success","data":{"deviceCode":"dc","userCode":"UC","verificationUri":"https://private-mailhub.com/cli/authorize","expiresIn":600,"interval":0}}`)
				return
			}
			pollCalls.Add(1)
			time.Sleep(50 * time.Millisecond)
		}))
		defer server.Close()
		client := api.NewClient(server.URL, "", "0.1.0")
		authorization, err := client.StartDeviceAuthorization(t.Context(), "Mac")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
		defer cancel()
		_, err = client.PollDeviceToken(ctx, authorization, time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("err=%v", err)
		}
		if pollCalls.Load() != 1 {
			t.Fatalf("poll calls=%d, want 1", pollCalls.Load())
		}
	})

	t.Run("첫 polling 전에 interval만큼 기다리고 deadline이면 요청하지 않는다", func(t *testing.T) {
		var pollCalls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/auth/cli/device" {
				_, _ = io.WriteString(w, `{"result":"success","data":{"deviceCode":"dc","userCode":"UC","verificationUri":"https://private-mailhub.com/cli/authorize","expiresIn":600,"interval":0}}`)
				return
			}
			pollCalls.Add(1)
			_, _ = io.WriteString(w, `{"result":"fail","error":"authorization_pending"}`)
		}))
		defer server.Close()
		client := api.NewClient(server.URL, "", "0.1.0")
		authorization, err := client.StartDeviceAuthorization(t.Context(), "Mac")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()
		_, err = client.PollDeviceToken(ctx, authorization, 100*time.Millisecond)
		if err == nil || pollCalls.Load() != 0 {
			t.Fatalf("err=%v poll calls=%d", err, pollCalls.Load())
		}
	})

	t.Run("교차 origin 307 토큰 리디렉션은 외부 호스트에 요청하지 않는다", func(t *testing.T) {
		var sourceTokenRequests atomic.Int64
		var redirectTargetRequests atomic.Int64
		redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectTargetRequests.Add(1)
			_, _ = io.WriteString(w, `{"result":"success","data":{"apiKey":"mhk_raw","keyId":"k1","expiresAt":"2030-01-01T00:00:00Z","scopes":["relay:read"]}}`)
		}))
		defer redirectTarget.Close()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/auth/cli/device":
				_, _ = io.WriteString(w, `{"result":"success","data":{"deviceCode":"dc","userCode":"UC","verificationUri":"https://private-mailhub.com/cli/authorize","expiresIn":600,"interval":0}}`)
			case "/api/auth/cli/device/token":
				sourceTokenRequests.Add(1)
				http.Redirect(w, r, redirectTarget.URL+"/api/auth/cli/device/token", http.StatusTemporaryRedirect)
			default:
				t.Errorf("unexpected source request path: %s", r.URL.Path)
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		client := api.NewClient(server.URL, "", "0.1.0")
		authorization, err := client.StartDeviceAuthorization(t.Context(), "Mac")
		if err != nil {
			t.Fatal("start device authorization failed")
		}
		_, pollErr := client.PollDeviceToken(t.Context(), authorization, time.Millisecond)
		if pollErr == nil || !strings.Contains(pollErr.Error(), "cross-origin redirect must not carry a request body") {
			t.Fatal("poll did not return the cross-origin request-body redirect-policy error")
		}
		if requests := sourceTokenRequests.Load(); requests != 1 {
			t.Fatalf("source token endpoint received %d request(s), want exactly one", requests)
		}

		if requests := redirectTargetRequests.Load(); requests != 0 {
			t.Fatalf("cross-origin redirect target received %d request(s)", requests)
		}
	})

	t.Run("poll proof는 start commitment와 일치하고 모든 polling에서 동일하게 유지된다", func(t *testing.T) {
		pollCalls := 0
		var startBody map[string]json.RawMessage
		var startBodyRaw string
		var pollSecrets []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/auth/cli/device" {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read start request body: %v", err)
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				startBodyRaw = string(body)
				if err := json.Unmarshal(body, &startBody); err != nil {
					t.Errorf("decode start request body: %v", err)
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				_, _ = io.WriteString(w, `{"result":"success","data":{"deviceCode":"dc","userCode":"UC","verificationUri":"https://private-mailhub.com/cli/authorize","expiresIn":600,"interval":0}}`)
				return
			}
			pollCalls++
			var requestBody struct {
				DeviceCode string `json:"deviceCode"`
				PollSecret string `json:"pollSecret"`
			}
			if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
				t.Errorf("decode poll request body: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if requestBody.DeviceCode != "dc" {
				t.Errorf("poll device code=%q, want dc", requestBody.DeviceCode)
			}
			pollSecrets = append(pollSecrets, requestBody.PollSecret)
			if pollCalls == 1 {
				_, _ = io.WriteString(w, `{"result":"fail","error":"authorization_pending"}`)
				return
			}
			if pollCalls == 2 {
				_, _ = io.WriteString(w, `{"result":"fail","error":"slow_down"}`)
				return
			}
			_, _ = io.WriteString(w, `{"result":"success","data":{"apiKey":"mhk_raw","keyId":"k1","expiresAt":"2030-01-01T00:00:00Z","scopes":["relay:read"]}}`)
		}))
		defer server.Close()
		client := api.NewClient(server.URL, "", "0.1.0")
		start, err := client.StartDeviceAuthorization(t.Context(), "Mac")
		if err != nil || start.DeviceCode != "dc" {
			t.Fatalf("device authorization was incomplete or failed: code present=%t err=%v", start.DeviceCode != "", err)
		}
		result, err := client.PollDeviceToken(t.Context(), start, time.Millisecond)
		if err != nil || result.APIKey != "mhk_raw" || result.KeyID != "k1" {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		if len(startBody) == 0 || startBody["pollSecretHash"] == nil {
			t.Fatalf("start request did not include pollSecretHash: %q", startBodyRaw)
		}
		if _, ok := startBody["pollSecret"]; ok {
			t.Fatalf("start request exposed raw poll proof: %q", startBodyRaw)
		}
		if len(pollSecrets) != 3 || pollSecrets[0] == "" {
			t.Fatalf("poll request count=%d or proof missing, want three requests with a proof", len(pollSecrets))
		}
		for _, secret := range pollSecrets[1:] {
			if secret != pollSecrets[0] {
				t.Fatal("poll proof changed between requests")
			}
		}
		if len(pollSecrets[0]) != 43 {
			t.Fatalf("poll proof length=%d, want a 43-character base64url value", len(pollSecrets[0]))
		}
		decodedProof, err := base64.RawURLEncoding.DecodeString(pollSecrets[0])
		if err != nil || len(decodedProof) != 32 || base64.RawURLEncoding.EncodeToString(decodedProof) != pollSecrets[0] {
			t.Fatal("poll proof was not a canonical 32-byte base64url value")
		}
		if strings.Contains(startBodyRaw, pollSecrets[0]) {
			t.Fatalf("start request included raw poll proof: %q", startBodyRaw)
		}
		var receivedHash string
		if err := json.Unmarshal(startBody["pollSecretHash"], &receivedHash); err != nil {
			t.Fatalf("decode start pollSecretHash: %v", err)
		}
		proofHash := sha256.Sum256([]byte(pollSecrets[0]))
		if receivedHash != hex.EncodeToString(proofHash[:]) {
			t.Fatal("start pollSecretHash does not match the SHA-256 of the poll proof")
		}
		serializedAuthorization, err := json.Marshal(start)
		if err != nil {
			t.Fatalf("marshal device authorization: %v", err)
		}
		if strings.Contains(string(serializedAuthorization), "pollSecret") || strings.Contains(string(serializedAuthorization), pollSecrets[0]) {
			t.Fatal("device authorization JSON exposed the poll proof")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, start), pollSecrets[0]) {
				t.Fatalf("device authorization formatting with %q exposed the poll proof", format)
			}
		}
	})

	t.Run("거부와 만료는 인증 오류로 구분된다", func(t *testing.T) {
		for _, code := range []string{"access_denied", "expired_token"} {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/auth/cli/device" {
					_, _ = io.WriteString(w, `{"result":"success","data":{"deviceCode":"dc","userCode":"UC","verificationUri":"https://private-mailhub.com/cli/authorize","expiresIn":600,"interval":0}}`)
					return
				}
				_, _ = io.WriteString(w, `{"result":"fail","error":"`+code+`"}`)
			}))
			client := api.NewClient(server.URL, "", "0.1.0")
			authorization, err := client.StartDeviceAuthorization(t.Context(), "Mac")
			if err != nil {
				server.Close()
				t.Fatal(err)
			}
			_, err = client.PollDeviceToken(t.Context(), authorization, time.Millisecond)
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
