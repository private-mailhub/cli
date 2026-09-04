package credentials

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	KeychainService = "private-mailhub.mailhub-cli"
	KeychainAccount = "default"
)

type Store interface {
	Save(token string) error
	Load() string
	Delete() error
}

type MemoryStore struct {
	mu    sync.RWMutex
	token string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (s *MemoryStore) Save(token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("token is required")
	}
	s.mu.Lock()
	s.token = token
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) Load() string {
	s.mu.RLock()
	token := s.token
	s.mu.RUnlock()
	return token
}

func (s *MemoryStore) Delete() error {
	s.mu.Lock()
	s.token = ""
	s.mu.Unlock()
	return nil
}

func ResolveToken(store Store) string {
	if token, ok := os.LookupEnv("MAILHUB_TOKEN"); ok {
		return strings.TrimSpace(token)
	}
	if store == nil {
		return ""
	}
	return strings.TrimSpace(store.Load())
}

func Logout(store Store, revoke func() error) error {
	if store == nil {
		return errors.New("credential store is required")
	}
	if revoke == nil {
		return errors.New("revoke operation is required")
	}
	if err := revoke(); err != nil {
		return err
	}
	return store.Delete()
}

func ExpiringSoon(expiresAt time.Time) bool {
	if expiresAt.IsZero() || expiresAt.Before(time.Now()) {
		return false
	}
	return !expiresAt.After(time.Now().Add(7 * 24 * time.Hour))
}
