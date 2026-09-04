//go:build darwin && cgo

package credentials

import (
	"errors"
	"strings"

	"github.com/keybase/go-keychain"
)

type KeychainStore struct {
	service string
	account string
}

func NewKeychainStore() *KeychainStore {
	return &KeychainStore{service: KeychainService, account: KeychainAccount}
}

func (s *KeychainStore) Save(token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("token is required")
	}
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(s.service)
	query.SetAccount(s.account)
	update := keychain.NewItem()
	update.SetData([]byte(token))
	if err := keychain.UpdateItem(query, update); err == nil {
		return nil
	} else if err != keychain.ErrorItemNotFound {
		return err
	}
	item := keychain.NewGenericPassword(s.service, s.account, "", []byte(token), "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	return keychain.AddItem(item)
}

func (s *KeychainStore) Load() string {
	data, err := keychain.GetGenericPassword(s.service, s.account, "", "")
	if err != nil {
		return ""
	}
	return string(data)
}

func (s *KeychainStore) Delete() error {
	err := keychain.DeleteGenericPasswordItem(s.service, s.account)
	if err == keychain.ErrorItemNotFound {
		return nil
	}
	return err
}

var _ Store = (*KeychainStore)(nil)
