package cli

import (
	"testing"

	"github.com/private-mailhub/mailhub-cli/internal/api"
	"github.com/private-mailhub/mailhub-cli/internal/credentials"
)

func TestStatusKey_현재토큰PublicID우선(t *testing.T) {
	publicID := "ab_cdEFghijKLMNopQRstu"
	if len(publicID) != 22 {
		t.Fatalf("fixture public id length=%d", len(publicID))
	}
	token := "mhk_" + publicID + "_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	keys := []api.Key{
		{ID: "unrelated", PublicID: "other-public-id", ExpiresAt: "2030-01-01T00:00:00Z"},
		{ID: "current", PublicID: publicID, ExpiresAt: "2030-02-01T00:00:00Z"},
	}
	keyID, expiresAt := statusKey(keys, credentials.Config{KeyID: "unrelated"}, token)
	if keyID != "current" || expiresAt != "2030-02-01T00:00:00Z" {
		t.Fatalf("keyID=%q expiresAt=%q", keyID, expiresAt)
	}
}

func TestAPIKeyPublicID_고정길이Base64URL(t *testing.T) {
	publicID := "ab_cdEFghijKLMNopQRstu"
	secret := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	if got := apiKeyPublicID("mhk_" + publicID + "_" + secret); got != publicID {
		t.Fatalf("public id=%q want=%q", got, publicID)
	}
	for _, malformed := range []string{"", "mhk_", "mhk_short_secret", "mhk_abcdefghijklmnopqrstuv", "mhk_abcdefghijklmnopqrstuv_secret"} {
		if got := apiKeyPublicID(malformed); got != "" {
			t.Errorf("malformed token %q returned %q", malformed, got)
		}
	}
}
