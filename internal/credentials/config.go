package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	APIURL    string `json:"apiUrl,omitempty"`
	KeyID     string `json:"keyId,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

func ConfigPath() (string, error) {
	configDir := os.Getenv("MAILHUB_CONFIG_DIR")
	if configDir == "" {
		var err error
		configDir, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("find user config directory: %w", err)
		}
	}
	return filepath.Join(configDir, "mailhub", "config.json"), nil
}

func LoadConfig() (Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	return config, nil
}

func SaveConfig(config Config) error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect config directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".config.json-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect temporary config: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect config: %w", err)
	}
	return syncDirectory(directory)
}

func DeleteConfig() error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete config: %w", err)
	}
	return nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open config directory: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}
