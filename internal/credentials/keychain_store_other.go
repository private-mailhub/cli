//go:build !darwin

package credentials

import "errors"

type KeychainStore struct{}

func NewKeychainStore() *KeychainStore {
	return &KeychainStore{}
}

func (s *KeychainStore) Save(Credential) error {
	return errors.New("macOS Keychain is unavailable on this platform")
}

func (s *KeychainStore) Load() (Credential, error) {
	return Credential{}, errors.New("macOS Keychain is unavailable on this platform")
}

func (s *KeychainStore) Delete() error {
	return errors.New("macOS Keychain is unavailable on this platform")
}

var _ Store = (*KeychainStore)(nil)
