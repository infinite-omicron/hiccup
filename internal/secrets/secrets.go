// Package secrets resolves credential references: plaintext, "env:VAR", or
// "keychain:service/account" (macOS Keychain, Windows Credential Manager, Linux Secret Service).
package secrets

import (
	"fmt"
	"os"
	"strings"

	"github.com/zalando/go-keyring"
)

const Service = "hiccup"

// Kind reports how a value is stored: "plain", "env", "keychain" or "" when empty.
func Kind(v string) string {
	switch {
	case v == "":
		return ""
	case strings.HasPrefix(v, "env:"):
		return "env"
	case strings.HasPrefix(v, "keychain:"):
		return "keychain"
	default:
		return "plain"
	}
}

// Resolve returns the secret a reference points to.
func Resolve(v string) (string, error) {
	switch Kind(v) {
	case "env":
		name := strings.TrimPrefix(v, "env:")
		s, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		return s, nil
	case "keychain":
		svc, acct, err := splitKeychain(v)
		if err != nil {
			return "", err
		}
		s, err := keyring.Get(svc, acct)
		if err != nil {
			return "", fmt.Errorf("keychain %s/%s: %w", svc, acct, err)
		}
		return s, nil
	default:
		return v, nil
	}
}

// Store saves a secret in the OS keychain and returns the reference to put in config.
func Store(account, secret string) (string, error) {
	if err := keyring.Set(Service, account, secret); err != nil {
		return "", err
	}
	return "keychain:" + Service + "/" + account, nil
}

// splitKeychain parses "keychain:service/account"; the account may itself contain "/".
func splitKeychain(v string) (string, string, error) {
	rest := strings.TrimPrefix(v, "keychain:")
	svc, acct, ok := strings.Cut(rest, "/")
	if !ok || svc == "" || acct == "" {
		return "", "", fmt.Errorf("bad keychain reference %q (want keychain:service/account)", v)
	}
	return svc, acct, nil
}
