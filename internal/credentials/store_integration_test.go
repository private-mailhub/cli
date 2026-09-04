package credentials_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/private-mailhub/mailhub-cli/internal/credentials"
)

func TestStore_자격증명우선순위와정리(t *testing.T) {
	t.Run("환경변수 토큰이 저장소 토큰보다 우선한다", func(t *testing.T) {
		store := credentials.NewMemoryStore()
		_ = store.Save(credentials.Credential{Token: "stored-token", APIURL: "https://private-mailhub.com"})
		t.Setenv("MAILHUB_TOKEN", "env-token")
		if got := credentials.ResolveToken(store); got != "env-token" {
			t.Fatalf("token=%q", got)
		}
	})
	t.Run("로그아웃 성공 시에만 로컬 키를 삭제한다", func(t *testing.T) {
		store := credentials.NewMemoryStore()
		_ = store.Save(credentials.Credential{Token: "token", APIURL: "https://private-mailhub.com"})
		if err := credentials.Logout(store, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if got, _ := store.Load(); got.Token != "" {
			t.Fatalf("token remains: %q", got)
		}
		_ = store.Save(credentials.Credential{Token: "token", APIURL: "https://private-mailhub.com"})
		if err := credentials.Logout(store, func() error { return errors.New("network") }); err == nil {
			t.Fatal("expected revoke error")
		}
		if got, _ := store.Load(); got.Token != "token" {
			t.Fatalf("token removed after failed revoke: %+v", got)
		}
	})
	t.Run("만료 7일 이내이면 경고 대상이다", func(t *testing.T) {
		if !credentials.ExpiringSoon(time.Now().Add(6 * 24 * time.Hour)) {
			t.Fatal("expected warning")
		}
		if credentials.ExpiringSoon(time.Now().Add(8 * 24 * time.Hour)) {
			t.Fatal("unexpected warning")
		}
	})
}

func TestStore_오류와origin보호(t *testing.T) {
	t.Run("Load 오류는 숨기지 않고 logout은 revoke를 건너뛴다", func(t *testing.T) {
		store := credentials.NewErrorStore(errors.New("keychain locked"))
		revoked := false
		if err := credentials.Logout(store, func() error { revoked = true; return nil }); err == nil || !strings.Contains(err.Error(), "keychain locked") {
			t.Fatalf("err=%v", err)
		}
		if revoked {
			t.Fatal("revoke called after Load failure")
		}
	})
	t.Run("저장 실패 시 이전 자격증명을 복구한다", func(t *testing.T) {
		store := credentials.NewMemoryStore()
		previous := credentials.Credential{Token: "old", APIURL: "https://private-mailhub.com"}
		_ = store.Save(previous)
		store.FailNextSave(errors.New("disk full"))
		if err := credentials.Replace(store, credentials.Credential{Token: "new", APIURL: "https://evil.example"}); err == nil {
			t.Fatal("expected save failure")
		}
		got, err := store.Load()
		if err != nil || got != previous {
			t.Fatalf("got=%+v err=%v", got, err)
		}
	})
	t.Run("저장된 토큰은 API origin에 묶이고 tampered config는 origin을 바꾸지 못한다", func(t *testing.T) {
		store := credentials.NewMemoryStore()
		_ = store.Save(credentials.Credential{Token: "secret", APIURL: "https://private-mailhub.com"})
		if got := credentials.ResolveAPIOrigin(store, "https://evil.example"); got != "https://private-mailhub.com" {
			t.Fatalf("origin=%q", got)
		}
	})
}
