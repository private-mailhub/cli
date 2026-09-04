package credentials

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	KeychainService = "private-mailhub.mailhub-cli"
	KeychainAccount = "default"
	DefaultAPIURL   = "https://private-mailhub.com"
)

type Credential struct {
	Token  string `json:"token"`
	APIURL string `json:"apiUrl"`
}

type Store interface {
	Save(credential Credential) error
	Load() (Credential, error)
	Delete() error
}

type MemoryStore struct {
	mu       sync.RWMutex
	value    Credential
	failSave error
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (s *MemoryStore) Save(credential Credential) error {
	if err := normalizeCredential(&credential); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSave != nil {
		err := s.failSave
		s.failSave = nil
		return err
	}
	s.value = credential
	return nil
}

func (s *MemoryStore) Load() (Credential, error) {
	s.mu.RLock()
	value := s.value
	s.mu.RUnlock()
	return value, nil
}

func (s *MemoryStore) Delete() error {
	s.mu.Lock()
	s.value = Credential{}
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) FailNextSave(err error) {
	s.mu.Lock()
	s.failSave = err
	s.mu.Unlock()
}

type ErrorStore struct {
	err error
}

func NewErrorStore(err error) *ErrorStore {
	return &ErrorStore{err: err}
}

func (s *ErrorStore) Save(Credential) error {
	return s.err
}

func (s *ErrorStore) Load() (Credential, error) {
	return Credential{}, s.err
}

func (s *ErrorStore) Delete() error {
	return s.err
}

func ResolveToken(store Store) string {
	if token, ok := os.LookupEnv("MAILHUB_TOKEN"); ok {
		return strings.TrimSpace(token)
	}
	if store == nil {
		return ""
	}
	credential, err := store.Load()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(credential.Token)
}

func ResolveAPIOrigin(store Store, override string) string {
	if store != nil {
		credential, err := store.Load()
		if err == nil && strings.TrimSpace(credential.Token) != "" {
			if origin, normalizeErr := NormalizeAPIOrigin(credential.APIURL); normalizeErr == nil {
				return origin
			}
		}
	}
	if origin, err := NormalizeAPIOrigin(override); err == nil {
		return origin
	}
	return DefaultAPIURL
}

func Logout(store Store, revoke func() error) error {
	if store == nil {
		return errors.New("credential store is required")
	}
	credential, err := store.Load()
	if err != nil {
		return err
	}
	if strings.TrimSpace(credential.Token) == "" {
		return nil
	}
	if revoke == nil {
		return errors.New("revoke operation is required")
	}
	if err := revoke(); err != nil {
		return err
	}
	return store.Delete()
}

func Replace(store Store, credential Credential) error {
	if store == nil {
		return errors.New("credential store is required")
	}
	previous, err := store.Load()
	if err != nil {
		return err
	}
	if err := store.Save(credential); err != nil {
		if restoreErr := restore(store, previous); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return err
	}
	return nil
}

func Restore(store Store, credential Credential) error {
	if store == nil {
		return errors.New("credential store is required")
	}
	return restore(store, credential)
}

func restore(store Store, credential Credential) error {
	if strings.TrimSpace(credential.Token) == "" {
		return store.Delete()
	}
	return store.Save(credential)
}

func NormalizeAPIOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = DefaultAPIURL
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("API URL must be an absolute origin")
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("API URL must not include a path or query")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && !(scheme == "http" && isLoopback(parsed.Hostname())) {
		return "", errors.New("API URL must use HTTPS")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", errors.New("API URL host is required")
	}
	port := parsed.Port()
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port), nil
	}
	if strings.Contains(host, ":") {
		return scheme + "://[" + host + "]", nil
	}
	return scheme + "://" + host, nil
}

func isLoopback(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func validateCredential(credential Credential) error {
	return normalizeCredential(&credential)
}

func normalizeCredential(credential *Credential) error {
	if credential == nil || strings.TrimSpace(credential.Token) == "" {
		return errors.New("token is required")
	}
	origin, err := NormalizeAPIOrigin(credential.APIURL)
	if err != nil {
		return err
	}
	credential.Token = strings.TrimSpace(credential.Token)
	credential.APIURL = origin
	return nil
}

func ExpiringSoon(expiresAt time.Time) bool {
	if expiresAt.IsZero() || expiresAt.Before(time.Now()) {
		return false
	}
	return !expiresAt.After(time.Now().Add(7 * 24 * time.Hour))
}

var _ Store = (*MemoryStore)(nil)
var _ Store = (*ErrorStore)(nil)
