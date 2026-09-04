//go:build darwin && cgo

package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/keybase/go-keychain"
)

type KeychainStore struct {
	service string
	account string
}

type keychainEnvelope struct {
	Token  string `json:"token"`
	APIURL string `json:"apiUrl"`
}

func NewKeychainStore() *KeychainStore {
	return &KeychainStore{service: KeychainService, account: KeychainAccount}
}

func (s *KeychainStore) Save(credential Credential) error {
	if err := validateCredential(credential); err != nil {
		return err
	}
	credential.Token = strings.TrimSpace(credential.Token)
	origin, err := NormalizeAPIOrigin(credential.APIURL)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(keychainEnvelope{Token: credential.Token, APIURL: origin})
	if err != nil {
		return err
	}
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(s.service)
	query.SetAccount(s.account)
	update := keychain.NewItem()
	update.SetData(payload)
	if err := keychain.UpdateItem(query, update); err == nil {
		return nil
	} else if err != keychain.ErrorItemNotFound {
		return err
	}
	item := keychain.NewGenericPassword(s.service, s.account, "", payload, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	return keychain.AddItem(item)
}

func (s *KeychainStore) Load() (Credential, error) {
	data, err := keychain.GetGenericPassword(s.service, s.account, "", "")
	if err != nil {
		if err == keychain.ErrorItemNotFound {
			return Credential{}, nil
		}
		return Credential{}, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return Credential{}, nil
	}
	var envelope keychainEnvelope
	if data[0] == '{' {
		if err := json.Unmarshal(data, &envelope); err != nil {
			return Credential{}, fmt.Errorf("decode Keychain credential: %w", err)
		}
		if strings.TrimSpace(envelope.Token) == "" {
			return Credential{}, errors.New("Keychain credential token is missing")
		}
		origin, normalizeErr := NormalizeAPIOrigin(envelope.APIURL)
		if normalizeErr != nil {
			return Credential{}, normalizeErr
		}
		return Credential{Token: strings.TrimSpace(envelope.Token), APIURL: origin}, nil
	}
	legacyToken := strings.TrimSpace(string(data))
	if legacyToken == "" {
		return Credential{}, nil
	}
	return Credential{Token: legacyToken, APIURL: DefaultAPIURL}, nil
}

func (s *KeychainStore) Delete() error {
	err := keychain.DeleteGenericPasswordItem(s.service, s.account)
	if err == keychain.ErrorItemNotFound {
		return nil
	}
	return err
}

var _ Store = (*KeychainStore)(nil)
