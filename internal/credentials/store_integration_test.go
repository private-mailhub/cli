package credentials_test

import (
	"errors"
	"testing"
	"time"

	"github.com/private-mailhub/mailhub-cli/internal/credentials"
)

func TestStore_자격증명우선순위와정리(t *testing.T) {
	t.Run("환경변수 토큰이 저장소 토큰보다 우선한다", func(t *testing.T) {
		store := credentials.NewMemoryStore()
		_ = store.Save("stored-token")
		t.Setenv("MAILHUB_TOKEN", "env-token")
		if got := credentials.ResolveToken(store); got != "env-token" {
			t.Fatalf("token=%q", got)
		}
	})
	t.Run("로그아웃 성공 시에만 로컬 키를 삭제한다", func(t *testing.T) {
		store := credentials.NewMemoryStore()
		_ = store.Save("token")
		if err := credentials.Logout(store, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if got := store.Load(); got != "" {
			t.Fatalf("token remains: %q", got)
		}
		_ = store.Save("token")
		if err := credentials.Logout(store, func() error { return errors.New("network") }); err == nil {
			t.Fatal("expected revoke error")
		}
		if got := store.Load(); got != "token" {
			t.Fatalf("token removed after failed revoke: %q", got)
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
