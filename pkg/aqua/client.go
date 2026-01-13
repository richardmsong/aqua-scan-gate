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
	"time"

	"github.com/google/go-containerregistry/pkg/name"
)

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

	// APIKey for authentication
	APIKey string

	// Registry is the Aqua registry name to use for scans
	Registry string

	// Timeout for API calls
	Timeout time.Duration

	// InsecureSkipVerify disables TLS verification (not recommended for production)
	InsecureSkipVerify bool
}

type aquaClient struct {
	config     Config
	httpClient *http.Client
}

// NewClient creates a new Aqua client
func NewClient(config Config) Client {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &aquaClient{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
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

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
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

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
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

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
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

	return registriesResp.Result, nil
}

func (c *aquaClient) FindRegistryByPrefix(ctx context.Context, containerRegistry string) (string, error) {
	// If a default registry is configured, use it
	if c.config.Registry != "" {
		return c.config.Registry, nil
	}

	registries, err := c.GetRegistries(ctx)
	if err != nil {
		return "", fmt.Errorf("getting registries: %w", err)
	}

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
				return reg.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no Aqua registry found for container registry %q", containerRegistry)
}
