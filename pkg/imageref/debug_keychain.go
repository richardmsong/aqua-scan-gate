// Package imageref provides shared utilities for extracting and processing
// container image references from Kubernetes pod specifications.
package imageref

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// DebugKeychain wraps a keychain and logs authentication attempts at V(2) verbosity.
// This is useful for debugging authentication issues with container registries.
// To enable debug logging, use --zap-log-level=2 or --zap-log-level=debug.
type DebugKeychain struct {
	inner  authn.Keychain
	name   string
	logger logr.Logger
}

// NewDebugKeychain creates a new debug keychain wrapper.
// Authentication attempts and results are logged at V(2) verbosity level.
func NewDebugKeychain(inner authn.Keychain, name string, logger logr.Logger) authn.Keychain {
	return &DebugKeychain{
		inner:  inner,
		name:   name,
		logger: logger.WithName("auth-debug").WithValues("keychain", name),
	}
}

// Resolve implements authn.Keychain.
func (d *DebugKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	d.logger.V(2).Info("Resolving credentials", "target", target.String())

	auth, err := d.inner.Resolve(target)
	if err != nil {
		d.logger.V(2).Info("Failed to resolve credentials", "target", target.String(), "error", err)
		return nil, err
	}

	if auth == authn.Anonymous {
		d.logger.V(2).Info("Resolved to Anonymous", "target", target.String())
		return auth, nil
	}

	// Wrap the authenticator to log when it's used
	return &debugAuthenticator{
		inner:  auth,
		target: target.String(),
		logger: d.logger,
	}, nil
}

// debugAuthenticator wraps an authenticator and logs when credentials are retrieved.
type debugAuthenticator struct {
	inner  authn.Authenticator
	target string
	logger logr.Logger
}

// Authorization implements authn.Authenticator.
func (d *debugAuthenticator) Authorization() (*authn.AuthConfig, error) {
	d.logger.V(2).Info("Getting authorization", "target", d.target)

	cfg, err := d.inner.Authorization()
	if err != nil {
		d.logger.V(2).Info("Failed to get authorization", "target", d.target, "error", err)
		return nil, err
	}

	// Log credential info without exposing secrets
	if cfg == nil {
		d.logger.V(2).Info("Got nil AuthConfig", "target", d.target)
	} else {
		d.logger.V(2).Info("Got credentials",
			"target", d.target,
			"hasUsername", cfg.Username != "",
			"hasPassword", cfg.Password != "",
			"hasToken", cfg.RegistryToken != "",
			"hasIdentityToken", cfg.IdentityToken != "",
			"maskedUsername", maskCredential(cfg.Username),
		)
	}

	return cfg, nil
}

// maskCredential masks a credential string for safe logging.
func maskCredential(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}

// LogWorkloadIdentityEnv logs Azure Workload Identity environment variables for debugging.
// This helps diagnose issues with ACR authentication via workload identity.
// Logs are emitted at V(2) verbosity level.
func LogWorkloadIdentityEnv(logger logr.Logger) {
	l := logger.V(2).WithName("auth-debug")
	l.Info("Azure Workload Identity environment check started")

	envVars := []string{
		"AZURE_CLIENT_ID",
		"AZURE_TENANT_ID",
		"AZURE_FEDERATED_TOKEN_FILE",
		"AZURE_AUTHORITY_HOST",
	}

	for _, env := range envVars {
		value := os.Getenv(env)
		if value == "" {
			l.Info("Environment variable not set", "var", env)
		} else if env == "AZURE_FEDERATED_TOKEN_FILE" {
			// Check if the file exists
			if _, err := os.Stat(value); err == nil {
				// Log first few characters of token for debugging
				if content, err := os.ReadFile(value); err == nil {
					tokenLen := len(content)
					preview := string(content)
					if len(preview) > 50 {
						preview = preview[:50] + "..."
					}
					l.Info("Token file found",
						"var", env,
						"path", value,
						"tokenBytes", tokenLen,
						"tokenPreview", preview,
					)
				} else {
					l.Info("Token file found but unreadable", "var", env, "path", value, "error", err)
				}
			} else {
				l.Info("Token file not found", "var", env, "path", value, "error", err)
			}
		} else if strings.Contains(env, "CLIENT_ID") {
			l.Info("Environment variable set", "var", env, "maskedValue", maskCredential(value))
		} else {
			l.Info("Environment variable set", "var", env, "value", value)
		}
	}

	l.Info("Azure Workload Identity environment check completed")
}

// LogResolverAttempt logs the start of a resolver attempt for an image.
// Logs are emitted at V(2) verbosity level.
func LogResolverAttempt(logger logr.Logger, image string, keychainNames []string) {
	logger.V(2).WithName("auth-debug").Info("Resolving image", "image", image, "keychainOrder", keychainNames)
}

// DebugMultiKeychain wraps multiple keychains and logs which one succeeds.
type DebugMultiKeychain struct {
	keychains []authn.Keychain
	names     []string
	logger    logr.Logger
}

// NewDebugMultiKeychain creates a multi-keychain wrapper with logging.
// Authentication attempts are logged at V(2) verbosity level.
func NewDebugMultiKeychain(logger logr.Logger, keychains ...NamedKeychain) authn.Keychain {
	var kcs []authn.Keychain
	var names []string
	for _, nk := range keychains {
		kcs = append(kcs, nk.Keychain)
		names = append(names, nk.Name)
	}
	return &DebugMultiKeychain{
		keychains: kcs,
		names:     names,
		logger:    logger.WithName("auth-debug"),
	}
}

// NamedKeychain pairs a keychain with a descriptive name.
type NamedKeychain struct {
	Keychain authn.Keychain
	Name     string
}

// Resolve implements authn.Keychain.
func (d *DebugMultiKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	d.logger.V(2).Info("Resolving through keychains", "target", target.String(), "keychainCount", len(d.keychains), "keychains", d.names)

	// Try each keychain in order
	for i, kc := range d.keychains {
		name := d.names[i]
		d.logger.V(2).Info("Trying keychain", "index", i+1, "total", len(d.keychains), "keychain", name)

		auth, err := kc.Resolve(target)
		if err != nil {
			d.logger.V(2).Info("Keychain error", "keychain", name, "error", err)
			continue
		}

		if auth == authn.Anonymous {
			d.logger.V(2).Info("Keychain returned Anonymous, trying next", "keychain", name)
			continue
		}

		// Check if this authenticator actually has credentials
		cfg, err := auth.Authorization()
		if err != nil {
			d.logger.V(2).Info("Error getting authorization", "keychain", name, "error", err)
			continue
		}

		if cfg == nil || (cfg.Username == "" && cfg.Password == "" && cfg.RegistryToken == "" && cfg.IdentityToken == "") {
			d.logger.V(2).Info("Empty credentials, trying next", "keychain", name)
			continue
		}

		d.logger.V(2).Info("Keychain succeeded",
			"keychain", name,
			"hasUsername", cfg.Username != "",
			"hasPassword", cfg.Password != "",
			"hasToken", cfg.RegistryToken != "",
			"hasIdentityToken", cfg.IdentityToken != "",
		)

		return auth, nil
	}

	d.logger.V(2).Info("No keychain provided credentials, returning Anonymous", "target", target.String())

	return authn.Anonymous, nil
}

// ParseRegistryFromImage extracts the registry from an image reference.
func ParseRegistryFromImage(image string) (string, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return "", fmt.Errorf("parsing image reference: %w", err)
	}
	return ref.Context().RegistryStr(), nil
}
