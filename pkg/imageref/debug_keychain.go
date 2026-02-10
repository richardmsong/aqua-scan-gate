// Package imageref provides shared utilities for extracting and processing
// container image references from Kubernetes pod specifications.
package imageref

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// DebugKeychain wraps a keychain and logs authentication attempts when verbose mode is enabled.
// This is useful for debugging authentication issues with container registries.
type DebugKeychain struct {
	inner   authn.Keychain
	name    string
	verbose bool
}

// NewDebugKeychain creates a new debug keychain wrapper.
// When verbose is true, it logs authentication attempts and results.
func NewDebugKeychain(inner authn.Keychain, name string, verbose bool) authn.Keychain {
	return &DebugKeychain{
		inner:   inner,
		name:    name,
		verbose: verbose,
	}
}

// Resolve implements authn.Keychain.
func (d *DebugKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if d.verbose {
		log.Printf("[AUTH-DEBUG] [%s] Resolving credentials for: %s", d.name, target.String())
	}

	auth, err := d.inner.Resolve(target)
	if err != nil {
		if d.verbose {
			log.Printf("[AUTH-DEBUG] [%s] Failed to resolve credentials for %s: %v", d.name, target.String(), err)
		}
		return nil, err
	}

	if auth == authn.Anonymous {
		if d.verbose {
			log.Printf("[AUTH-DEBUG] [%s] Resolved to Anonymous for: %s", d.name, target.String())
		}
		return auth, nil
	}

	// Wrap the authenticator to log when it's used
	return &debugAuthenticator{
		inner:        auth,
		keychainName: d.name,
		target:       target.String(),
		verbose:      d.verbose,
	}, nil
}

// debugAuthenticator wraps an authenticator and logs when credentials are retrieved.
type debugAuthenticator struct {
	inner        authn.Authenticator
	keychainName string
	target       string
	verbose      bool
}

// Authorization implements authn.Authenticator.
func (d *debugAuthenticator) Authorization() (*authn.AuthConfig, error) {
	if d.verbose {
		log.Printf("[AUTH-DEBUG] [%s] Getting authorization for: %s", d.keychainName, d.target)
	}

	cfg, err := d.inner.Authorization()
	if err != nil {
		if d.verbose {
			log.Printf("[AUTH-DEBUG] [%s] Failed to get authorization for %s: %v", d.keychainName, d.target, err)
		}
		return nil, err
	}

	if d.verbose {
		// Log credential info without exposing secrets
		if cfg == nil {
			log.Printf("[AUTH-DEBUG] [%s] Got nil AuthConfig for: %s", d.keychainName, d.target)
		} else {
			hasUsername := cfg.Username != ""
			hasPassword := cfg.Password != ""
			hasToken := cfg.RegistryToken != ""
			hasIdentityToken := cfg.IdentityToken != ""

			log.Printf("[AUTH-DEBUG] [%s] Got credentials for %s: username=%v, password=%v, token=%v, identityToken=%v",
				d.keychainName, d.target, hasUsername, hasPassword, hasToken, hasIdentityToken)

			if hasUsername {
				// Log masked username
				log.Printf("[AUTH-DEBUG] [%s] Username: %s", d.keychainName, maskCredential(cfg.Username))
			}
		}
	}

	return cfg, nil
}

// maskCredential masks a credential string for safe logging.
func maskCredential(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}

// LogWorkloadIdentityEnv logs Azure Workload Identity environment variables for debugging.
// This helps diagnose issues with ACR authentication via workload identity.
func LogWorkloadIdentityEnv() {
	log.Println("[AUTH-DEBUG] === Azure Workload Identity Environment ===")

	envVars := []string{
		"AZURE_CLIENT_ID",
		"AZURE_TENANT_ID",
		"AZURE_FEDERATED_TOKEN_FILE",
		"AZURE_AUTHORITY_HOST",
	}

	for _, env := range envVars {
		value := os.Getenv(env)
		if value == "" {
			log.Printf("[AUTH-DEBUG]   %s: <not set>", env)
		} else if env == "AZURE_FEDERATED_TOKEN_FILE" {
			// Check if the file exists
			if _, err := os.Stat(value); err == nil {
				log.Printf("[AUTH-DEBUG]   %s: %s (file exists)", env, value)
				// Log first few characters of token for debugging
				if content, err := os.ReadFile(value); err == nil {
					tokenLen := len(content)
					log.Printf("[AUTH-DEBUG]   Token file size: %d bytes", tokenLen)
					if tokenLen > 0 {
						preview := string(content)
						if len(preview) > 50 {
							preview = preview[:50] + "..."
						}
						log.Printf("[AUTH-DEBUG]   Token preview: %s", preview)
					}
				}
			} else {
				log.Printf("[AUTH-DEBUG]   %s: %s (FILE NOT FOUND: %v)", env, value, err)
			}
		} else if strings.Contains(env, "CLIENT_ID") {
			log.Printf("[AUTH-DEBUG]   %s: %s", env, maskCredential(value))
		} else {
			log.Printf("[AUTH-DEBUG]   %s: %s", env, value)
		}
	}

	log.Println("[AUTH-DEBUG] =============================================")
}

// LogResolverAttempt logs the start of a resolver attempt for an image.
func LogResolverAttempt(image string, keychainNames []string) {
	log.Printf("[AUTH-DEBUG] === Resolving image: %s ===", image)
	log.Printf("[AUTH-DEBUG] Keychain order: %v", keychainNames)
}

// DebugMultiKeychain wraps multiple keychains and logs which one succeeds.
type DebugMultiKeychain struct {
	keychains []authn.Keychain
	names     []string
	verbose   bool
}

// NewDebugMultiKeychain creates a multi-keychain wrapper with logging.
func NewDebugMultiKeychain(verbose bool, keychains ...NamedKeychain) authn.Keychain {
	var kcs []authn.Keychain
	var names []string
	for _, nk := range keychains {
		kcs = append(kcs, nk.Keychain)
		names = append(names, nk.Name)
	}
	return &DebugMultiKeychain{
		keychains: kcs,
		names:     names,
		verbose:   verbose,
	}
}

// NamedKeychain pairs a keychain with a descriptive name.
type NamedKeychain struct {
	Keychain authn.Keychain
	Name     string
}

// Resolve implements authn.Keychain.
func (d *DebugMultiKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if d.verbose {
		log.Printf("[AUTH-DEBUG] Resolving %s through %d keychains: %v", target.String(), len(d.keychains), d.names)
	}

	// Try each keychain in order
	for i, kc := range d.keychains {
		name := d.names[i]
		if d.verbose {
			log.Printf("[AUTH-DEBUG] Trying keychain [%d/%d]: %s", i+1, len(d.keychains), name)
		}

		auth, err := kc.Resolve(target)
		if err != nil {
			if d.verbose {
				log.Printf("[AUTH-DEBUG]   [%s] Error: %v", name, err)
			}
			continue
		}

		if auth == authn.Anonymous {
			if d.verbose {
				log.Printf("[AUTH-DEBUG]   [%s] Returned Anonymous, trying next", name)
			}
			continue
		}

		// Check if this authenticator actually has credentials
		cfg, err := auth.Authorization()
		if err != nil {
			if d.verbose {
				log.Printf("[AUTH-DEBUG]   [%s] Error getting authorization: %v", name, err)
			}
			continue
		}

		if cfg == nil || (cfg.Username == "" && cfg.Password == "" && cfg.RegistryToken == "" && cfg.IdentityToken == "") {
			if d.verbose {
				log.Printf("[AUTH-DEBUG]   [%s] Empty credentials, trying next", name)
			}
			continue
		}

		if d.verbose {
			log.Printf("[AUTH-DEBUG]   [%s] SUCCESS - found credentials", name)
			log.Printf("[AUTH-DEBUG]   Credentials: username=%v, password=%v, token=%v, identityToken=%v",
				cfg.Username != "", cfg.Password != "", cfg.RegistryToken != "", cfg.IdentityToken != "")
		}

		return auth, nil
	}

	if d.verbose {
		log.Printf("[AUTH-DEBUG] No keychain provided credentials for %s, returning Anonymous", target.String())
	}

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
