package aqua

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
)

// DefaultCacheTTL is the default time-to-live for cached registry data
const DefaultCacheTTL = 1 * time.Hour

// ScanStatus represents the status returned by Aqua
type ScanStatus string

const (
	StatusNotFound ScanStatus = "not_found"
	StatusFound    ScanStatus = "found"
)

// ScanResult contains the results from Aqua
// With v2 API, we only care about whether the image was found (scanned) or not
type ScanResult struct {
	Status ScanStatus
	Image  string
	Digest string
}

// Registry represents an Aqua registry configuration
type Registry struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Description   string   `json:"description"`
	URL           string   `json:"url"`
	Prefixes      []string `json:"prefixes"`
	DefaultPrefix string   `json:"default_prefix"`
}

// RegistryMirror represents a mapping from a source registry to a mirror
// For example, mapping docker.io to artifactory.internal.com/docker-remote
type RegistryMirror struct {
	// Source is the original registry to be mirrored (e.g., "docker.io", "gcr.io")
	Source string
	// Mirror is the target mirror URL (e.g., "artifactory.internal.com/docker-remote")
	Mirror string
}

// RegistriesResponse is the response from GET /api/v2/registries
type RegistriesResponse struct {
	Count    int        `json:"count"`
	Page     int        `json:"page"`
	PageSize int        `json:"pagesize"`
	Result   []Registry `json:"result"`
}

// Client interface for Aqua operations
type Client interface {
	// GetScanResult retrieves existing scan results for an image
	GetScanResult(ctx context.Context, image, digest string) (*ScanResult, error)

	// TriggerScan initiates a new scan for an image
	TriggerScan(ctx context.Context, image, digest string) (string, error)

	// GetRegistries retrieves all configured registries from Aqua
	GetRegistries(ctx context.Context) ([]Registry, error)

	// FindRegistryByPrefix finds the Aqua registry name that matches a container registry prefix
	FindRegistryByPrefix(ctx context.Context, containerRegistry string) (string, error)
}

// Config holds Aqua client configuration
type Config struct {
	// BaseURL is the Aqua server URL
	BaseURL string

	// APIKey for authentication (deprecated, use Auth.Token instead)
	// Kept for backward compatibility
	APIKey string

	// Auth contains authentication configuration
	Auth AuthConfig

	// Registry is the Aqua registry name to use for scans
	Registry string

	// RegistryMirrors maps source registries to their mirrors for airgapped environments
	// Example: docker.io -> artifactory.internal.com/docker-remote
	RegistryMirrors []RegistryMirror

	// Timeout for API calls
	Timeout time.Duration

	// InsecureSkipVerify disables TLS verification (not recommended for production)
	InsecureSkipVerify bool

	// CacheTTL is the time-to-live for cached registry data (default: 1 hour)
	CacheTTL time.Duration

	// Verbose enables debug logging for authentication
	Verbose bool
}

// registryCache holds cached registry data with timestamp
type registryCache struct {
	registries []Registry
	fetchedAt  time.Time
}

type aquaClient struct {
	config       Config
	httpClient   *http.Client
	tokenManager *TokenManager

	// Cache for registries
	cacheMu sync.RWMutex
	cache   *registryCache
}

// NewClient creates a new Aqua client
func NewClient(config Config) Client {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = DefaultCacheTTL
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	// Handle backward compatibility: if APIKey is set but Auth.APIKey is not configured
	if config.APIKey != "" && config.Auth.APIKey == "" {
		config.Auth.APIKey = config.APIKey
	}

	tokenManager := NewTokenManager(config.BaseURL, config.Auth, httpClient, config.Verbose)

	return &aquaClient{
		config:       config,
		httpClient:   httpClient,
		tokenManager: tokenManager,
	}
}

// ApplyRegistryMirror applies registry mirror mappings to a container registry and image name.
// If the container registry matches a mirror source, it returns the mirrored registry and
// adjusted image name (prepending any path prefix from the mirror URL).
// Returns the original values if no matching mirror is found.
func ApplyRegistryMirror(containerRegistry, imageName string, mirrors []RegistryMirror) (mirroredRegistry, adjustedImageName string) {
	if len(mirrors) == 0 {
		return containerRegistry, imageName
	}

	// Normalize the container registry for comparison
	normalizedRegistry := normalizeRegistryURL(containerRegistry)

	for _, mirror := range mirrors {
		normalizedSource := normalizeRegistryURL(mirror.Source)

		// Check for exact match or alias match (docker.io vs index.docker.io)
		if normalizedRegistry == normalizedSource ||
			(isDockerHubAlias(normalizedRegistry) && isDockerHubAlias(normalizedSource)) {
			// Parse the mirror URL to extract the host and any path prefix
			mirrorHost, mirrorPathPrefix := parseMirrorURL(mirror.Mirror)

			// Adjust the image name by prepending the mirror path prefix
			if mirrorPathPrefix != "" {
				adjustedImageName = mirrorPathPrefix + "/" + imageName
			} else {
				adjustedImageName = imageName
			}

			return mirrorHost, adjustedImageName
		}
	}

	return containerRegistry, imageName
}

// normalizeRegistryURL normalizes a registry URL by removing protocol and trailing slashes
func normalizeRegistryURL(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimSuffix(url, "/")
	return url
}

// isDockerHubAlias returns true if the registry is a Docker Hub alias
func isDockerHubAlias(registry string) bool {
	return registry == "docker.io" || registry == "index.docker.io"
}

// parseMirrorURL splits a mirror URL into host and path prefix.
// For example, "artifactory.internal.com/docker-remote" returns
// ("artifactory.internal.com", "docker-remote")
func parseMirrorURL(mirrorURL string) (host, pathPrefix string) {
	mirrorURL = normalizeRegistryURL(mirrorURL)

	// Find the first slash to separate host from path prefix
	slashIdx := strings.Index(mirrorURL, "/")
	if slashIdx == -1 {
		// No path prefix, just the host
		return mirrorURL, ""
	}

	return mirrorURL[:slashIdx], mirrorURL[slashIdx+1:]
}

// ParseRegistryMirrors parses a comma-separated string of registry mirror mappings
// Format: "source1=mirror1,source2=mirror2"
// Example: "docker.io=artifactory.internal.com/docker-remote,gcr.io=artifactory.internal.com/gcr-remote"
func ParseRegistryMirrors(mirrorsStr string) ([]RegistryMirror, error) {
	if mirrorsStr == "" {
		return nil, nil
	}

	var mirrors []RegistryMirror
	pairs := strings.Split(mirrorsStr, ",")

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid registry mirror format %q: expected 'source=mirror'", pair)
		}

		source := strings.TrimSpace(parts[0])
		mirror := strings.TrimSpace(parts[1])

		if source == "" || mirror == "" {
			return nil, fmt.Errorf("invalid registry mirror %q: source and mirror cannot be empty", pair)
		}

		mirrors = append(mirrors, RegistryMirror{
			Source: source,
			Mirror: mirror,
		})
	}

	return mirrors, nil
}

// parseImageReference extracts container registry and image parts from a full image reference
// using go-containerregistry/pkg/name for proper parsing.
// Example: "richardmsong/jfrog-token-exchanger" with digest "sha256:abc123..."
// returns container registry (e.g., "ghcr.io"), image name, and @sha256:... as tag
func parseImageReference(image, digest string) (containerRegistry, imageName, tag string, err error) {
	// Parse the image reference using go-containerregistry
	ref, parseErr := name.ParseReference(image)
	if parseErr != nil {
		return "", "", "", fmt.Errorf("parsing image reference: %w", parseErr)
	}

	// Extract the container registry from the parsed reference (e.g., "ghcr.io", "docker.io")
	containerRegistry = ref.Context().RegistryStr()

	// Get the repository path (without registry)
	imageName = ref.Context().RepositoryStr()

	// Tag is the digest prefixed with @
	tag = "@" + digest

	return containerRegistry, imageName, tag, nil
}

func (c *aquaClient) GetScanResult(ctx context.Context, image, digest string) (*ScanResult, error) {
	// GET /api/v2/images/{registry}/{image}/{tag}
	// where tag is @sha256:...
	// If not 404, consider it scanned/passed

	containerRegistry, imageName, tag, err := parseImageReference(image, digest)
	if err != nil {
		return nil, err
	}

	// Apply registry mirrors if configured (for airgapped environments)
	containerRegistry, imageName = ApplyRegistryMirror(containerRegistry, imageName, c.config.RegistryMirrors)

	// Look up the Aqua registry name from the container registry
	aquaRegistry, err := c.FindRegistryByPrefix(ctx, containerRegistry)
	if err != nil {
		return nil, fmt.Errorf("finding Aqua registry for %q: %w", containerRegistry, err)
	}

	// Build URL using url.JoinPath for proper URL construction
	apiURL, err := url.JoinPath(c.config.BaseURL, "api", "v2", "images", aquaRegistry, imageName, tag)
	if err != nil {
		return nil, fmt.Errorf("building API URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Get bearer token (this will fetch via HMAC-signed request if needed)
	token, err := c.tokenManager.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// 404 means not scanned yet
	if resp.StatusCode == http.StatusNotFound {
		return &ScanResult{
			Status: StatusNotFound,
			Image:  image,
			Digest: digest,
		}, nil
	}

	// Any other non-error response means the image has been scanned
	// We don't care about the enforcement - Aqua enforcer handles that
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &ScanResult{
			Status: StatusFound,
			Image:  image,
			Digest: digest,
		}, nil
	}

	// Read response body for error details
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
}

// triggerScanRequest is the request body for POST /api/v2/images
type triggerScanRequest struct {
	Registry string `json:"registry"`
	Image    string `json:"image"`
}

func (c *aquaClient) TriggerScan(ctx context.Context, image, digest string) (string, error) {
	// POST /api/v2/images
	// Body: {"registry": "...", "image": "imagename@sha256:..."}

	containerRegistry, imageName, _, err := parseImageReference(image, digest)
	if err != nil {
		return "", err
	}

	// Apply registry mirrors if configured (for airgapped environments)
	containerRegistry, imageName = ApplyRegistryMirror(containerRegistry, imageName, c.config.RegistryMirrors)

	// Look up the Aqua registry name from the container registry
	aquaRegistry, err := c.FindRegistryByPrefix(ctx, containerRegistry)
	if err != nil {
		return "", fmt.Errorf("finding Aqua registry for %q: %w", containerRegistry, err)
	}

	// Build the image reference with digest for the API
	// Format: imagename@sha256:...
	imageWithDigest := imageName + "@" + digest

	reqBody := triggerScanRequest{
		Registry: aquaRegistry,
		Image:    imageWithDigest,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request body: %w", err)
	}

	// Build URL using url.JoinPath for proper URL construction
	apiURL, err := url.JoinPath(c.config.BaseURL, "api", "v2", "images")
	if err != nil {
		return "", fmt.Errorf("building API URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	// Get bearer token (this will fetch via HMAC-signed request if needed)
	token, err := c.tokenManager.GetToken(ctx)
	if err != nil {
		return "", fmt.Errorf("getting auth token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// 201 Created is the expected response
	if resp.StatusCode == http.StatusCreated {
		// Return a composite ID for tracking (registry/image@digest)
		return fmt.Sprintf("%s/%s", aquaRegistry, imageWithDigest), nil
	}

	// Read response body for error details
	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBodyBytes))
}

func (c *aquaClient) GetRegistries(ctx context.Context) ([]Registry, error) {
	// Check cache first with read lock
	c.cacheMu.RLock()
	if c.cache != nil && time.Since(c.cache.fetchedAt) < c.config.CacheTTL {
		registries := c.cache.registries
		c.cacheMu.RUnlock()
		return registries, nil
	}
	c.cacheMu.RUnlock()

	// Cache miss or expired, fetch from API
	return c.fetchRegistries(ctx)
}

// fetchRegistries fetches registries from the API and updates the cache
func (c *aquaClient) fetchRegistries(ctx context.Context) ([]Registry, error) {
	// GET /api/v2/registries
	// Returns all configured registries in Aqua

	apiURL, err := url.JoinPath(c.config.BaseURL, "api", "v2", "registries")
	if err != nil {
		return nil, fmt.Errorf("building API URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Get bearer token (this will fetch via HMAC-signed request if needed)
	token, err := c.tokenManager.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var registriesResp RegistriesResponse
	if err := json.NewDecoder(resp.Body).Decode(&registriesResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Update cache with write lock
	c.cacheMu.Lock()
	c.cache = &registryCache{
		registries: registriesResp.Result,
		fetchedAt:  time.Now(),
	}
	c.cacheMu.Unlock()

	return registriesResp.Result, nil
}

// refreshCache forces a cache refresh by fetching registries from the API
func (c *aquaClient) refreshCache(ctx context.Context) ([]Registry, error) {
	return c.fetchRegistries(ctx)
}

func (c *aquaClient) FindRegistryByPrefix(ctx context.Context, containerRegistry string) (string, error) {
	// If a default registry is configured, use it
	if c.config.Registry != "" {
		return c.config.Registry, nil
	}

	// First try with cached registries
	registries, err := c.GetRegistries(ctx)
	if err != nil {
		return "", fmt.Errorf("getting registries: %w", err)
	}

	if name := c.findRegistryInList(containerRegistry, registries); name != "" {
		return name, nil
	}

	// Not found in cache - refresh cache and try again in case it's stale
	registries, err = c.refreshCache(ctx)
	if err != nil {
		return "", fmt.Errorf("refreshing registry cache: %w", err)
	}

	if name := c.findRegistryInList(containerRegistry, registries); name != "" {
		return name, nil
	}

	return "", fmt.Errorf("no Aqua registry found for container registry %q", containerRegistry)
}

// findRegistryInList searches for a matching registry in the given list
func (c *aquaClient) findRegistryInList(containerRegistry string, registries []Registry) string {
	// Normalize the container registry for comparison
	normalizedRegistry := strings.TrimPrefix(containerRegistry, "https://")
	normalizedRegistry = strings.TrimPrefix(normalizedRegistry, "http://")
	normalizedRegistry = strings.TrimSuffix(normalizedRegistry, "/")

	// Search for a registry whose prefixes contain the container registry
	for _, reg := range registries {
		for _, prefix := range reg.Prefixes {
			// Normalize the prefix for comparison
			normalizedPrefix := strings.TrimPrefix(prefix, "https://")
			normalizedPrefix = strings.TrimPrefix(normalizedPrefix, "http://")
			normalizedPrefix = strings.TrimSuffix(normalizedPrefix, "/")

			// Check if the container registry matches or starts with the prefix
			if normalizedRegistry == normalizedPrefix ||
				strings.HasPrefix(normalizedRegistry, normalizedPrefix+"/") ||
				strings.HasPrefix(normalizedPrefix, normalizedRegistry) {
				return reg.Name
			}
		}
	}

	return ""
}
