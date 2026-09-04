package platform

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
)

func OpenBrowser(rawURL string) error {
	if err := validateURL(rawURL, ""); err != nil {
		return err
	}
	var command string
	if runtime.GOOS == "darwin" {
		command = "open"
	} else if runtime.GOOS == "windows" {
		command = "rundll32"
	} else {
		command = "xdg-open"
	}
	if runtime.GOOS == "windows" {
		return exec.Command(command, "url.dll,FileProtocolHandler", rawURL).Run()
	}
	return exec.Command(command, rawURL).Run()
}

func ValidateVerificationURL(rawURL, _ string) error {
	return validateURL(rawURL, "")
}

func validateURL(rawURL, baseScheme string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("verification URL is invalid")
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !isLoopback(parsed.Hostname()) {
			return fmt.Errorf("verification URL must use HTTPS")
		}
	}
	if baseScheme == "https" && parsed.Scheme != "https" {
		return fmt.Errorf("verification URL must use HTTPS")
	}
	return nil
}

func isLoopback(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}
