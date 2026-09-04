package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/private-mailhub/mailhub-cli/internal/api"
	"github.com/private-mailhub/mailhub-cli/internal/credentials"
	"github.com/private-mailhub/mailhub-cli/internal/platform"
	"github.com/spf13/cobra"
)

const (
	Version = "0.1.0"

	ExitOK    = 0
	ExitAPI   = 1
	ExitUsage = 2
	ExitAuth  = 3
)

type app struct {
	out     io.Writer
	errOut  io.Writer
	store   credentials.Store
	apiFlag string
}

type authState struct {
	client     *api.Client
	credential credentials.Credential
	metadata   credentials.Config
	fromEnv    bool
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func Execute(args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	application := &app{
		out:    stdout,
		errOut: stderr,
		store:  credentials.NewKeychainStore(),
	}
	root := application.rootCommand()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		code := exitCode(err)
		fmt.Fprintln(stderr, redactSecrets(err.Error()))
		return code
	}
	return ExitOK
}

func (a *app) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "mailhub",
		Short:         "Mailhub command-line interface",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(a.out)
	root.SetErr(a.errOut)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError(err)
	})
	root.PersistentFlags().StringVar(&a.apiFlag, "api-url", "", "Mailhub API origin")
	root.AddCommand(a.versionCommand())
	root.AddCommand(a.completionCommand(root))
	root.AddCommand(a.authCommand())
	root.AddCommand(a.aliasCommand())
	return root
}

func (a *app) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CLI version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "mailhub %s\n", Version)
			return err
		},
	}
}

func (a *app) completionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "completion <zsh|bash|fish>",
		Short: "Generate shell completion script",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError(errors.New("completion requires one shell: zsh, bash, or fish"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			switch args[0] {
			case "zsh":
				err = root.GenZshCompletion(cmd.OutOrStdout())
			case "bash":
				err = root.GenBashCompletion(cmd.OutOrStdout())
			case "fish":
				err = root.GenFishCompletion(cmd.OutOrStdout(), true)
			default:
				return usageError(fmt.Errorf("unsupported shell %q; use zsh, bash, or fish", args[0]))
			}
			return err
		},
	}
}

func (a *app) authCommand() *cobra.Command {
	auth := &cobra.Command{
		Use:   "auth",
		Short: "Manage Mailhub authentication",
	}
	auth.AddCommand(a.loginCommand())
	auth.AddCommand(a.statusCommand())
	auth.AddCommand(a.logoutCommand())
	keys := &cobra.Command{
		Use:   "keys",
		Short: "Manage API keys",
	}
	keys.AddCommand(a.keysListCommand())
	keys.AddCommand(a.keysRevokeCommand())
	auth.AddCommand(keys)
	return auth
}

func (a *app) loginCommand() *cobra.Command {
	var noBrowser bool
	var deviceName string
	login := &cobra.Command{
		Use:   "login",
		Short: "Authenticate this device",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(deviceName) == "" {
				deviceName = hostname()
			}
			if utf8.RuneCountInString(deviceName) > 100 {
				return usageError(errors.New("device name must be 100 characters or fewer"))
			}
			client, err := a.publicClient()
			if err != nil {
				return err
			}
			authorization, err := client.StartDeviceAuthorization(cmd.Context(), deviceName)
			if err != nil {
				return apiError(err)
			}
			if err := api.ValidateVerificationURL(authorization.VerificationURI); err != nil {
				return apiError(err)
			}
			if noBrowser {
				if err := printDeviceInstructions(cmd.OutOrStdout(), authorization); err != nil {
					return err
				}
			} else if err := platform.OpenBrowser(authorization.VerificationURI); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "could not open browser: %s\n", redactSecrets(err.Error()))
				if err := printDeviceInstructions(cmd.OutOrStdout(), authorization); err != nil {
					return err
				}
			}
			pollContext, cancel := devicePollContext(cmd.Context(), authorization.ExpiresIn)
			defer cancel()
			interval := time.Duration(authorization.Interval) * time.Second
			deviceToken, err := client.PollDeviceToken(pollContext, authorization.DeviceCode, interval)
			if err != nil {
				if pollContext.Err() == context.DeadlineExceeded {
					return authError(errors.New("device authorization expired"))
				}
				return deviceFlowError(err)
			}
			if err := a.saveCredentials(deviceToken, clientBaseURL(client)); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Authenticated successfully (key %s, expires %s).\n", deviceToken.KeyID, deviceToken.ExpiresAt)
			return err
		},
	}
	login.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the approval URL instead of opening a browser")
	login.Flags().StringVar(&deviceName, "device-name", "", "Name of this device")
	return login
}

func (a *app) statusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := a.authClient()
			if err != nil {
				return err
			}
			metadata := credentials.Config{}
			if !state.fromEnv {
				metadata, err = credentials.LoadConfig()
				if err != nil {
					return apiError(err)
				}
				a.warnExpiry(metadata, false)
			}
			keys, err := state.client.ListKeys(cmd.Context())
			if err != nil {
				return apiError(err)
			}
			if state.fromEnv {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "Authenticated via MAILHUB_TOKEN.")
				return err
			}
			keyID, expiresAt := statusKey(keys, metadata, state.credential.Token)
			if keyID == "" {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "Authenticated (no active API key metadata found).")
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Authenticated\nKey ID: %s\nExpires: %s\n", keyID, expiresAt)
			return err
		},
	}
}

func (a *app) logoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the current API key and clear local credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			credential, fromEnv, err := a.loadCredential()
			if err != nil {
				return apiError(err)
			}
			if credential.Token == "" {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "Not authenticated.")
				return err
			}
			client, err := a.clientForCredential(credential, fromEnv)
			if err != nil {
				return err
			}
			if fromEnv {
				revokeErr := client.RevokeCurrentKey(cmd.Context())
				if revokeErr != nil && !isTerminalAuthError(revokeErr) {
					return apiError(revokeErr)
				}
				if revokeErr != nil {
					_, err = fmt.Fprintln(cmd.OutOrStdout(), "API key was already expired or revoked.")
					if guidanceErr := printEnvTokenGuidance(cmd.ErrOrStderr()); err == nil {
						err = guidanceErr
					}
					return err
				}
				if err := printEnvTokenGuidance(cmd.ErrOrStderr()); err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "Logged out.")
				return err
			}
			revokeErr := credentials.Logout(a.store, func() error {
				return client.RevokeCurrentKey(cmd.Context())
			})
			if revokeErr != nil {
				if !isTerminalAuthError(revokeErr) {
					return apiError(revokeErr)
				}
				if err := a.store.Delete(); err != nil {
					return apiError(err)
				}
			}
			if err := credentials.DeleteConfig(); err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "Logged out.")
			return err
		},
	}
}

func (a *app) keysListCommand() *cobra.Command {
	var jsonOutput bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List API keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := a.authClient()
			if err != nil {
				return err
			}
			a.warnExpiry(state.metadata, state.fromEnv)
			keys, err := state.client.ListKeys(cmd.Context())
			if err != nil {
				return apiError(err)
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), keys)
			}
			return printKeys(cmd.OutOrStdout(), keys)
		},
	}
	list.Flags().BoolVar(&jsonOutput, "json", false, "Output JSON")
	return list
}

func (a *app) keysRevokeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <key-id>",
		Short: "Revoke an API key",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
				return usageError(errors.New("revoke requires a key id"))
			}
			if !isPositiveInteger(args[0]) {
				return usageError(errors.New("key id must be a positive integer"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := a.authClient()
			if err != nil {
				return err
			}
			a.warnExpiry(state.metadata, state.fromEnv)
			if err := state.client.RevokeKey(cmd.Context(), args[0]); err != nil {
				return apiError(err)
			}
			if state.metadata.KeyID == args[0] {
				if !state.fromEnv {
					if err := a.store.Delete(); err != nil {
						return apiError(err)
					}
					if err := credentials.DeleteConfig(); err != nil {
						return apiError(err)
					}
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Revoked key %s.\n", args[0])
			return err
		},
	}
}

func (a *app) aliasCommand() *cobra.Command {
	alias := &cobra.Command{
		Use:   "alias",
		Short: "Manage relay email aliases",
	}
	alias.AddCommand(a.aliasListCommand())
	alias.AddCommand(a.aliasCreateCommand())
	alias.AddCommand(a.aliasActiveCommand("on", true))
	alias.AddCommand(a.aliasActiveCommand("off", false))
	alias.AddCommand(a.aliasLabelCommand())
	return alias
}

func (a *app) aliasListCommand() *cobra.Command {
	var jsonOutput bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List relay email aliases",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := a.authClient()
			if err != nil {
				return err
			}
			a.warnExpiry(state.metadata, state.fromEnv)
			aliases, err := state.client.ListAliases(cmd.Context())
			if err != nil {
				return apiError(err)
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), aliases)
			}
			return printAliases(cmd.OutOrStdout(), aliases)
		},
	}
	list.Flags().BoolVar(&jsonOutput, "json", false, "Output JSON")
	return list
}

func (a *app) aliasCreateCommand() *cobra.Command {
	var label string
	var jsonOutput bool
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a relay email alias",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if utf8.RuneCountInString(label) > 100 {
				return usageError(errors.New("label must be 100 characters or fewer"))
			}
			state, err := a.authClient()
			if err != nil {
				return err
			}
			a.warnExpiry(state.metadata, state.fromEnv)
			alias, err := state.client.CreateAlias(cmd.Context(), label)
			if err != nil {
				return apiError(err)
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), alias)
			}
			return printCreatedAlias(cmd.OutOrStdout(), alias)
		},
	}
	create.Flags().StringVar(&label, "label", "", "Description for the alias")
	create.Flags().BoolVar(&jsonOutput, "json", false, "Output JSON")
	return create
}

func (a *app) aliasActiveCommand(name string, active bool) *cobra.Command {
	return &cobra.Command{
		Use:   name + " <id-or-email>",
		Short: aliasActiveDescription(active),
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
				return usageError(errors.New(name + " requires an alias id or email"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := a.authClient()
			if err != nil {
				return err
			}
			a.warnExpiry(state.metadata, state.fromEnv)
			id, err := a.resolveAliasID(cmd.Context(), state.client, args[0])
			if err != nil {
				return err
			}
			if err := state.client.SetAliasActive(cmd.Context(), id, active); err != nil {
				return apiError(err)
			}
			stateLabel := "disabled"
			if active {
				stateLabel = "enabled"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Alias %s %s.\n", id, stateLabel)
			return err
		},
	}
}

func aliasActiveDescription(active bool) string {
	if active {
		return "Enable a relay email alias"
	}
	return "Disable a relay email alias"
}

func (a *app) aliasLabelCommand() *cobra.Command {
	var clear bool
	label := &cobra.Command{
		Use:   "label <id-or-email> [label]",
		Short: "Set or clear an alias label",
		Args: func(_ *cobra.Command, args []string) error {
			if clear {
				if len(args) != 1 {
					return usageError(errors.New("--clear cannot be combined with a label"))
				}
				return nil
			}
			if len(args) != 2 || strings.TrimSpace(args[1]) == "" {
				return usageError(errors.New("label requires an alias id or email and a label"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if !clear && utf8.RuneCountInString(args[1]) > 100 {
				return usageError(errors.New("label must be 100 characters or fewer"))
			}
			state, err := a.authClient()
			if err != nil {
				return err
			}
			a.warnExpiry(state.metadata, state.fromEnv)
			id, err := a.resolveAliasID(cmd.Context(), state.client, args[0])
			if err != nil {
				return err
			}
			description := ""
			if !clear {
				description = args[1]
			}
			if err := state.client.UpdateAliasDescription(cmd.Context(), id, description); err != nil {
				return apiError(err)
			}
			if clear {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Cleared label for alias %s.\n", id)
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Updated label for alias %s.\n", id)
			}
			return err
		},
	}
	label.Flags().BoolVar(&clear, "clear", false, "Clear the alias label")
	return label
}

func (a *app) resolveAliasID(ctx context.Context, client *api.Client, identifier string) (string, error) {
	if isPositiveInteger(identifier) {
		return identifier, nil
	}
	aliases, err := client.ListAliases(ctx)
	if err != nil {
		return "", apiError(err)
	}
	for _, alias := range aliases {
		if alias.RelayEmail == identifier {
			return alias.ID, nil
		}
	}
	return "", usageError(fmt.Errorf("alias %q was not found", identifier))
}

func (a *app) publicClient() (*api.Client, error) {
	baseURL, _, err := a.explicitOrigin()
	if err != nil {
		return nil, err
	}
	return api.NewClient(baseURL, "", Version), nil
}

func (a *app) authClient() (authState, error) {
	credential, fromEnv, err := a.loadCredential()
	if err != nil {
		return authState{}, apiError(err)
	}
	if credential.Token == "" {
		return authState{}, authRequiredError()
	}
	client, err := a.clientForCredential(credential, fromEnv)
	if err != nil {
		return authState{}, err
	}
	state := authState{client: client, credential: credential, fromEnv: fromEnv}
	if !fromEnv {
		metadata, metadataErr := credentials.LoadConfig()
		if metadataErr != nil {
			return authState{}, apiError(metadataErr)
		}
		state.metadata = metadata
	}
	return state, nil
}

func (a *app) loadCredential() (credentials.Credential, bool, error) {
	if token, ok := os.LookupEnv("MAILHUB_TOKEN"); ok {
		return credentials.Credential{Token: strings.TrimSpace(token)}, true, nil
	}
	credential, err := a.store.Load()
	if err != nil {
		return credentials.Credential{}, false, err
	}
	credential.Token = strings.TrimSpace(credential.Token)
	return credential, false, nil
}

func (a *app) clientForCredential(credential credentials.Credential, fromEnv bool) (*api.Client, error) {
	if fromEnv {
		origin, _, err := a.explicitOrigin()
		if err != nil {
			return nil, err
		}
		return api.NewClient(origin, credential.Token, Version), nil
	}
	boundOrigin, err := credentials.NormalizeAPIOrigin(credential.APIURL)
	if err != nil {
		return nil, apiError(err)
	}
	explicitOrigin, hasExplicit, err := a.explicitOrigin()
	if err != nil {
		return nil, err
	}
	if hasExplicit && explicitOrigin != boundOrigin {
		return nil, usageError(errors.New("API URL does not match the saved credential; run `mailhub auth login` again"))
	}
	return api.NewClient(boundOrigin, credential.Token, Version), nil
}

func (a *app) explicitOrigin() (string, bool, error) {
	if strings.TrimSpace(a.apiFlag) != "" {
		origin, err := credentials.NormalizeAPIOrigin(a.apiFlag)
		if err != nil {
			return "", true, usageError(err)
		}
		return origin, true, nil
	}
	if value, ok := os.LookupEnv("MAILHUB_API_URL"); ok && strings.TrimSpace(value) != "" {
		origin, err := credentials.NormalizeAPIOrigin(value)
		if err != nil {
			return "", true, usageError(err)
		}
		return origin, true, nil
	}
	return credentials.DefaultAPIURL, false, nil
}

func (a *app) saveCredentials(deviceToken api.DeviceToken, baseURL string) error {
	origin, err := credentials.NormalizeAPIOrigin(baseURL)
	if err != nil {
		return apiError(err)
	}
	newCredential := credentials.Credential{Token: deviceToken.APIKey, APIURL: origin}
	previousCredential, err := a.store.Load()
	if err != nil {
		return apiError(err)
	}
	previousMetadata, err := credentials.LoadConfig()
	if err != nil {
		return apiError(err)
	}
	if err := a.store.Save(newCredential); err != nil {
		if restoreErr := credentials.Restore(a.store, previousCredential); restoreErr != nil {
			return apiError(errors.Join(err, restoreErr))
		}
		return apiError(err)
	}
	newMetadata := credentials.Config{KeyID: deviceToken.KeyID, ExpiresAt: deviceToken.ExpiresAt}
	if err := credentials.SaveConfig(newMetadata); err != nil {
		restoreErr := credentials.Restore(a.store, previousCredential)
		metadataRestoreErr := restoreMetadata(previousMetadata)
		if restoreErr != nil || metadataRestoreErr != nil {
			return apiError(errors.Join(err, restoreErr, metadataRestoreErr))
		}
		return apiError(err)
	}
	return nil
}

func restoreMetadata(metadata credentials.Config) error {
	if metadata.KeyID == "" && metadata.ExpiresAt == "" {
		return credentials.DeleteConfig()
	}
	return credentials.SaveConfig(metadata)
}

func (a *app) warnExpiry(metadata credentials.Config, fromEnv bool) {
	if fromEnv || metadata.ExpiresAt == "" {
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, metadata.ExpiresAt)
	if err == nil && credentials.ExpiringSoon(expiresAt) {
		_, _ = fmt.Fprintf(a.errOut, "warning: API key expires on %s\n", metadata.ExpiresAt)
	}
}

func printDeviceInstructions(out io.Writer, authorization api.DeviceAuthorization) error {
	_, err := fmt.Fprintf(out, "Open %s and enter code %s.\n", authorization.VerificationURI, authorization.UserCode)
	return err
}

func printAliases(out io.Writer, aliases []api.Alias) error {
	if len(aliases) == 0 {
		_, err := fmt.Fprintln(out, "No aliases.")
		return err
	}
	if _, err := fmt.Fprintln(out, "ID\tEMAIL\tACTIVE\tLABEL\tFORWARDS\tCREATED"); err != nil {
		return err
	}
	for _, alias := range aliases {
		active := "off"
		if alias.IsActive {
			active = "on"
		}
		if _, err := fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\n", alias.ID, alias.RelayEmail, active, aliasDescription(alias), alias.ForwardCount, alias.CreatedAt); err != nil {
			return err
		}
	}
	return nil
}

func aliasDescription(alias api.Alias) string {
	if alias.Description == nil {
		return ""
	}
	return *alias.Description
}

func printCreatedAlias(out io.Writer, alias api.CreatedAlias) error {
	_, err := fmt.Fprintf(out, "Created alias %s (%s).\n", alias.ID, alias.RelayEmail)
	return err
}

func printEnvTokenGuidance(out io.Writer) error {
	_, err := fmt.Fprintln(out, "MAILHUB_TOKEN is set; remove it from your environment when you are finished.")
	return err
}

func printKeys(out io.Writer, keys []api.Key) error {
	if len(keys) == 0 {
		_, err := fmt.Fprintln(out, "No API keys.")
		return err
	}
	if _, err := fmt.Fprintln(out, "ID\tEXPIRES\tREVOKED\tSCOPES"); err != nil {
		return err
	}
	for _, key := range keys {
		revoked := ""
		if key.RevokedAt != nil {
			revoked = *key.RevokedAt
		}
		if _, err := fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", key.ID, key.ExpiresAt, revoked, strings.Join(key.Scopes, ",")); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func statusKey(keys []api.Key, metadata credentials.Config, token string) (string, string) {
	publicID := apiKeyPublicID(token)
	if publicID != "" {
		for _, key := range keys {
			if key.PublicID == publicID && key.RevokedAt == nil {
				return key.ID, key.ExpiresAt
			}
		}
	}
	if metadata.KeyID != "" {
		for _, key := range keys {
			if key.ID == metadata.KeyID && key.RevokedAt == nil {
				return key.ID, key.ExpiresAt
			}
		}
	}
	return "", ""
}

func apiKeyPublicID(token string) string {
	const (
		prefixLength   = len("mhk_")
		publicIDLength = 22
		secretLength   = 43
	)
	if len(token) != prefixLength+publicIDLength+1+secretLength || !strings.HasPrefix(token, "mhk_") {
		return ""
	}
	if token[prefixLength+publicIDLength] != '_' {
		return ""
	}
	publicID := token[prefixLength : prefixLength+publicIDLength]
	secret := token[prefixLength+publicIDLength+1:]
	if !isBase64URL(publicID) || !isBase64URL(secret) {
		return ""
	}
	return publicID
}

func isBase64URL(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func devicePollContext(parent context.Context, expiresIn int) (context.Context, context.CancelFunc) {
	if expiresIn <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, time.Duration(expiresIn)*time.Second)
}

func normalizeBaseURL(rawURL string) (string, error) {
	origin, err := credentials.NormalizeAPIOrigin(rawURL)
	if err != nil {
		return "", usageError(err)
	}
	return origin, nil
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "Mac"
	}
	return strings.TrimSpace(name)
}

func clientBaseURL(client *api.Client) string {
	return client.BaseURL()
}

func isPositiveInteger(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	for _, character := range value {
		if character != '0' {
			return true
		}
	}
	return false
}

func usageError(err error) error {
	return &exitError{code: ExitUsage, err: err}
}

func authError(err error) error {
	return &exitError{code: ExitAuth, err: err}
}

func apiError(err error) error {
	if err == nil {
		return nil
	}
	if existing, ok := err.(*exitError); ok {
		return existing
	}
	if isTerminalAuthError(err) {
		return authError(err)
	}
	return &exitError{code: ExitAPI, err: err}
}

func deviceFlowError(err error) error {
	if isTerminalAuthError(err) {
		return authError(err)
	}
	return apiError(err)
}

func authRequiredError() error {
	return authError(errors.New("authentication required; run `mailhub auth login`"))
}

func isTerminalAuthError(err error) bool {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == "API_KEY_EXPIRED" || apiErr.Code == "API_KEY_REVOKED" || apiErr.Code == "access_denied" || apiErr.Code == "expired_token" || apiErr.Status == 401
	}
	return false
}

var tokenPattern = regexp.MustCompile(`(?i)mhk_[A-Za-z0-9_-]+`)

func redactSecrets(value string) string {
	return tokenPattern.ReplaceAllString(value, "[REDACTED]")
}

func exitCode(err error) int {
	var coded *exitError
	if errors.As(err, &coded) && coded.code != 0 {
		return coded.code
	}
	if isCobraUsageError(err) {
		return ExitUsage
	}
	return ExitAPI
}

func isCobraUsageError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"unknown command",
		"unknown flag",
		"unknown shorthand flag",
		"flag needs an argument",
		"requires",
		"accepts",
		"arg(s)",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
