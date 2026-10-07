package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultBaseURL = "https://private-mailhub.com"

const HTTPTimeout = 15 * time.Second

type Client struct {
	baseURL    string
	token      string
	version    string
	httpClient *http.Client
}

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != "" && e.Message != "" && e.Message != e.Code {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	if e.Code != "" {
		return e.Code
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Status > 0 {
		return fmt.Sprintf("request failed with status %d", e.Status)
	}
	return "request failed"
}

type Alias struct {
	ID              string  `json:"id"`
	RelayEmail      string  `json:"relayEmail"`
	IsActive        bool    `json:"isActive"`
	Description     *string `json:"description"`
	ForwardCount    string  `json:"forwardCount"`
	LastForwardedAt *string `json:"lastForwardedAt"`
	CreatedAt       string  `json:"createdAt"`
	UpdatedAt       *string `json:"updatedAt"`
}

type CreatedAlias struct {
	ID         string `json:"id"`
	RelayEmail string `json:"relayEmail"`
	IsActive   bool   `json:"isActive"`
	// Description is either the server-provided string or nil when the
	// response explicitly contains JSON null.
	Description any    `json:"description"`
	CreatedAt   string `json:"createdAt"`
}

func (a *Alias) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID              json.RawMessage `json:"id"`
		RelayEmail      json.RawMessage `json:"relayEmail"`
		IsActive        bool            `json:"isActive"`
		Description     json.RawMessage `json:"description"`
		ForwardCount    json.RawMessage `json:"forwardCount"`
		LastForwardedAt json.RawMessage `json:"lastForwardedAt"`
		CreatedAt       json.RawMessage `json:"createdAt"`
		UpdatedAt       json.RawMessage `json:"updatedAt"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	a.ID, err = decodeString(raw.ID)
	if err != nil {
		return fmt.Errorf("alias id: %w", err)
	}
	a.RelayEmail, err = decodeString(raw.RelayEmail)
	if err != nil {
		return fmt.Errorf("relay email: %w", err)
	}
	a.IsActive = raw.IsActive
	if len(raw.Description) != 0 && string(raw.Description) != "null" {
		description, decodeErr := decodeString(raw.Description)
		err = decodeErr
		if err != nil {
			return fmt.Errorf("alias description: %w", err)
		}
		a.Description = &description
	} else {
		a.Description = nil
	}
	a.ForwardCount, err = decodeString(raw.ForwardCount)
	if err != nil {
		return fmt.Errorf("forward count: %w", err)
	}
	a.LastForwardedAt, err = decodeOptionalString(raw.LastForwardedAt)
	if err != nil {
		return fmt.Errorf("last forwarded at: %w", err)
	}
	a.CreatedAt, err = decodeString(raw.CreatedAt)
	if err != nil {
		return fmt.Errorf("created at: %w", err)
	}
	a.UpdatedAt, err = decodeOptionalString(raw.UpdatedAt)
	if err != nil {
		return fmt.Errorf("updated at: %w", err)
	}
	return nil
}

type Key struct {
	ID         string   `json:"id"`
	PublicID   string   `json:"publicId"`
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes"`
	Source     string   `json:"source"`
	LastUsedAt *string  `json:"lastUsedAt"`
	ExpiresAt  string   `json:"expiresAt"`
	RevokedAt  *string  `json:"revokedAt"`
	CreatedAt  string   `json:"createdAt"`
}

func (k *Key) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID         json.RawMessage `json:"id"`
		PublicID   json.RawMessage `json:"publicId"`
		Name       json.RawMessage `json:"name"`
		Scopes     []string        `json:"scopes"`
		Source     json.RawMessage `json:"source"`
		LastUsedAt json.RawMessage `json:"lastUsedAt"`
		ExpiresAt  json.RawMessage `json:"expiresAt"`
		RevokedAt  json.RawMessage `json:"revokedAt"`
		CreatedAt  json.RawMessage `json:"createdAt"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	k.ID, err = decodeString(raw.ID)
	if err != nil {
		return fmt.Errorf("key id: %w", err)
	}
	k.PublicID, err = decodeString(raw.PublicID)
	if err != nil {
		return fmt.Errorf("key public id: %w", err)
	}
	k.Name, err = decodeString(raw.Name)
	if err != nil {
		return fmt.Errorf("key name: %w", err)
	}
	k.Source, err = decodeString(raw.Source)
	if err != nil {
		return fmt.Errorf("key source: %w", err)
	}
	k.LastUsedAt, err = decodeOptionalString(raw.LastUsedAt)
	if err != nil {
		return fmt.Errorf("key last used at: %w", err)
	}
	k.ExpiresAt, err = decodeString(raw.ExpiresAt)
	if err != nil {
		return fmt.Errorf("key expiry: %w", err)
	}
	k.RevokedAt, err = decodeOptionalString(raw.RevokedAt)
	if err != nil {
		return fmt.Errorf("key revoked at: %w", err)
	}
	k.CreatedAt, err = decodeString(raw.CreatedAt)
	if err != nil {
		return fmt.Errorf("key created at: %w", err)
	}
	k.Scopes = append([]string(nil), raw.Scopes...)
	return nil
}

type DeviceAuthorization struct {
	DeviceCode      string `json:"deviceCode"`
	UserCode        string `json:"userCode"`
	VerificationURI string `json:"verificationUri"`
	ExpiresIn       int    `json:"expiresIn"`
	Interval        int    `json:"interval"`
	pollSecret      string
}

func (DeviceAuthorization) String() string {
	return "DeviceAuthorization{redacted}"
}

func (DeviceAuthorization) GoString() string {
	return "DeviceAuthorization{redacted}"
}

type DeviceToken struct {
	APIKey    string   `json:"apiKey"`
	KeyID     string   `json:"keyId"`
	ExpiresAt string   `json:"expiresAt"`
	Scopes    []string `json:"scopes"`
}

func NewClient(baseURL, token, version string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	token = strings.TrimSpace(token)
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if version == "" {
		version = "0.1.0"
	}
	return &Client{
		baseURL:    baseURL,
		token:      token,
		version:    version,
		httpClient: newHTTPClient(),
	}
}

func (c *Client) BaseURL() string {
	if c == nil {
		return ""
	}
	return c.baseURL
}

func (c *Client) ListAliases(ctx context.Context) ([]Alias, error) {
	var aliases []Alias
	if err := c.doJSON(ctx, http.MethodGet, "/api/relay-emails", nil, &aliases); err != nil {
		return nil, err
	}
	return aliases, nil
}

func (c *Client) CreateAlias(ctx context.Context, description string) (CreatedAlias, error) {
	body := map[string]string{}
	if description != "" {
		body["description"] = description
	}
	var alias CreatedAlias
	if err := c.doJSON(ctx, http.MethodPost, "/api/relay-emails/create", body, &alias); err != nil {
		return CreatedAlias{}, err
	}
	return alias, nil
}

func (c *Client) ListKeys(ctx context.Context) ([]Key, error) {
	var keys []Key
	if err := c.doJSON(ctx, http.MethodGet, "/api/api-keys", nil, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (c *Client) RevokeKey(ctx context.Context, keyID string) error {
	if err := validatePathValue(keyID, "key id"); err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, "/api/api-keys/"+url.PathEscape(keyID), nil, nil)
}

func (c *Client) RevokeCurrentKey(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/api-keys/current", nil, nil)
}

func (c *Client) SetAliasActive(ctx context.Context, id string, active bool) error {
	if err := validatePathValue(id, "alias id"); err != nil {
		return err
	}
	body := struct {
		IsActive bool `json:"isActive"`
	}{IsActive: active}
	return c.doJSON(ctx, http.MethodPatch, "/api/relay-emails/"+url.PathEscape(id)+"/active", body, nil)
}

func (c *Client) UpdateAliasDescription(ctx context.Context, id, description string) error {
	if err := validatePathValue(id, "alias id"); err != nil {
		return err
	}
	body := struct {
		Description string `json:"description"`
	}{Description: description}
	return c.doJSON(ctx, http.MethodPatch, "/api/relay-emails/"+url.PathEscape(id)+"/description", body, nil)
}

func (c *Client) StartDeviceAuthorization(ctx context.Context, deviceName string) (DeviceAuthorization, error) {
	deviceName = strings.TrimSpace(deviceName)
	if deviceName == "" {
		return DeviceAuthorization{}, errors.New("device name is required")
	}
	pollProof, err := newPollProof()
	if err != nil {
		return DeviceAuthorization{}, err
	}
	pollSecretHash := sha256.Sum256([]byte(pollProof))
	body := struct {
		ClientName     string `json:"clientName"`
		DeviceName     string `json:"deviceName"`
		CLIVersion     string `json:"cliVersion"`
		PollSecretHash string `json:"pollSecretHash"`
	}{
		ClientName:     "mailhub-cli",
		DeviceName:     deviceName,
		CLIVersion:     c.version,
		PollSecretHash: hex.EncodeToString(pollSecretHash[:]),
	}
	var authorization DeviceAuthorization
	if err := c.doJSON(ctx, http.MethodPost, "/api/auth/cli/device", body, &authorization); err != nil {
		return DeviceAuthorization{}, err
	}
	if authorization.DeviceCode == "" || authorization.VerificationURI == "" {
		return DeviceAuthorization{}, errors.New("server returned an incomplete device authorization")
	}
	authorization.pollSecret = pollProof
	return authorization, nil
}

func (c *Client) PollDeviceToken(ctx context.Context, authorization DeviceAuthorization, interval time.Duration) (DeviceToken, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(authorization.DeviceCode) == "" {
		return DeviceToken{}, errors.New("device code is required")
	}
	if strings.TrimSpace(authorization.pollSecret) == "" {
		return DeviceToken{}, errors.New("device poll proof is missing")
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if err := wait(ctx, interval); err != nil {
		return DeviceToken{}, err
	}
	for {
		body := struct {
			DeviceCode string `json:"deviceCode"`
			PollSecret string `json:"pollSecret"`
		}{
			DeviceCode: authorization.DeviceCode,
			PollSecret: authorization.pollSecret,
		}
		var token DeviceToken
		err := c.doJSON(ctx, http.MethodPost, "/api/auth/cli/device/token", body, &token)
		if err == nil {
			if token.APIKey == "" || token.KeyID == "" {
				return DeviceToken{}, errors.New("server returned an incomplete API key")
			}
			return token, nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			return DeviceToken{}, err
		}
		switch apiErr.Code {
		case "authorization_pending":
			if err := wait(ctx, interval); err != nil {
				return DeviceToken{}, err
			}
		case "slow_down":
			interval += 5 * time.Second
			if err := wait(ctx, interval); err != nil {
				return DeviceToken{}, err
			}
		default:
			return DeviceToken{}, err
		}
	}
}

func newPollProof() (string, error) {
	proof := make([]byte, 32)
	if _, err := rand.Read(proof); err != nil {
		return "", fmt.Errorf("generate device poll proof: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(proof), nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, output any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	requestURL, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return fmt.Errorf("build request URL: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, requestBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "mailhub-cli/"+c.version)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer response.Body.Close()
	responseData, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	var envelope struct {
		Result  string          `json:"result"`
		Data    json.RawMessage `json:"data"`
		Error   json.RawMessage `json:"error"`
		Message json.RawMessage `json:"message"`
	}
	if len(bytes.TrimSpace(responseData)) > 0 {
		if err := json.Unmarshal(responseData, &envelope); err != nil {
			if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
				return &APIError{Status: response.StatusCode, Message: http.StatusText(response.StatusCode)}
			}
			return fmt.Errorf("decode response: %w", err)
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices || envelope.Result == "fail" {
		return newAPIError(response.StatusCode, envelope.Error, envelope.Data, envelope.Message)
	}
	if envelope.Result != "" && envelope.Result != "success" {
		return &APIError{Status: response.StatusCode, Message: "unexpected response result"}
	}
	if output == nil || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(envelope.Data, output); err != nil {
		return fmt.Errorf("decode response data: %w", err)
	}
	return nil
}

func newAPIError(status int, rawCode, rawData, rawMessage json.RawMessage) *APIError {
	code := decodeErrorValue(rawCode)
	message := firstErrorMessage(rawData, rawMessage, rawCode)
	if code == "" && isStableErrorCode(message) {
		code = message
	}
	return &APIError{
		Status:  status,
		Code:    code,
		Message: message,
	}
}

func isStableErrorCode(value string) bool {
	switch value {
	case "authorization_pending", "slow_down", "access_denied", "expired_token", "API_KEY_EXPIRED", "API_KEY_REVOKED":
		return true
	default:
		return false
	}
}

func firstErrorMessage(values ...json.RawMessage) string {
	for _, value := range values {
		if message := decodeErrorValue(value); message != "" {
			return message
		}
	}
	return "request failed"
}

func decodeErrorValue(value json.RawMessage) string {
	if len(value) == 0 || string(value) == "null" {
		return ""
	}
	var textValue string
	if json.Unmarshal(value, &textValue) == nil {
		return textValue
	}
	var objectValue struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(value, &objectValue) == nil {
		if objectValue.Message != "" {
			return objectValue.Message
		}
		return objectValue.Error
	}
	return ""
}

func decodeString(value json.RawMessage) (string, error) {
	if len(value) == 0 || string(value) == "null" {
		return "", nil
	}
	var textValue string
	if err := json.Unmarshal(value, &textValue); err == nil {
		return textValue, nil
	}
	var number json.Number
	if err := json.Unmarshal(value, &number); err == nil {
		return number.String(), nil
	}
	return "", fmt.Errorf("expected string or number")
}

func decodeOptionalString(value json.RawMessage) (*string, error) {
	if len(value) == 0 || string(value) == "null" {
		return nil, nil
	}
	decoded, err := decodeString(value)
	if err != nil {
		return nil, err
	}
	return &decoded, nil
}

func validatePathValue(value, fieldName string) error {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "/?#") {
		return fmt.Errorf("%s is invalid", fieldName)
	}
	return nil
}

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) SetHTTPClient(client *http.Client) {
	if client != nil {
		c.httpClient = configureHTTPClient(client)
	}
}

func ValidateVerificationURL(rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return errors.New("verification URL is invalid")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && !(scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return errors.New("verification URL must use HTTPS")
	}
	return nil
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: HTTPTimeout, CheckRedirect: redirectPolicy}
}

func configureHTTPClient(client *http.Client) *http.Client {
	configured := *client
	if configured.Timeout <= 0 || configured.Timeout > HTTPTimeout {
		configured.Timeout = HTTPTimeout
	}
	configured.CheckRedirect = redirectPolicy
	return &configured
}

func redirectPolicy(request *http.Request, previous []*http.Request) error {
	if request.URL.User != nil {
		return errors.New("redirect URL must not contain userinfo")
	}
	if len(previous) == 0 {
		return nil
	}
	last := previous[len(previous)-1]
	if isHTTPSDowngrade(last.URL, request.URL) {
		return errors.New("redirect must not downgrade HTTPS")
	}
	if !sameOrigin(last.URL, request.URL) {
		request.Header.Del("Authorization")
		if hasRequestBody(request) {
			return errors.New("cross-origin redirect must not carry a request body")
		}
		return nil
	}
	if authorization := last.Header.Get("Authorization"); authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	return nil
}

func hasRequestBody(request *http.Request) bool {
	return request.Body != nil && request.Body != http.NoBody
}

func isHTTPSDowngrade(source, target *url.URL) bool {
	if !strings.EqualFold(source.Scheme, "https") {
		return false
	}
	return !strings.EqualFold(target.Scheme, "https")
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		left.Port() == right.Port()
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}
