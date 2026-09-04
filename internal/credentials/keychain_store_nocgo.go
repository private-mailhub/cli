//go:build darwin && !cgo

package credentials

import "errors"

type KeychainStore struct{}

func NewKeychainStore() *KeychainStore {
	return &KeychainStore{}
}

func (s *KeychainStore) Save(string) error {
	return errors.New("macOS Keychain is unavailable without cgo")
}

func (s *KeychainStore) Load() string {
	return ""
}

func (s *KeychainStore) Delete() error {
	return errors.New("macOS Keychain is unavailable without cgo")
}

var _ Store = (*KeychainStore)(nil)
