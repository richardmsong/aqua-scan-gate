package aqua

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
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

// Client interface for Aqua operations
type Client interface {
	// GetScanResult retrieves existing scan results for an image
	GetScanResult(ctx context.Context, image, digest string) (*ScanResult, error)

	// TriggerScan initiates a new scan for an image
	TriggerScan(ctx context.Context, image, digest string) (string, error)
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

// parseImageReference extracts registry and image parts from a full image reference
// Example: "richardmsong/jfrog-token-exchanger" with digest "sha256:abc123..."
// returns registry from config, image name, and @sha256:... as tag
func parseImageReference(image, digest, defaultRegistry string) (registry, imageName, tag string) {
	// Use the registry from config or default
	registry = defaultRegistry
	if registry == "" {
		registry = "docker.io"
	}

	// The image name is the full image path without registry prefix if present
	imageName = image

	// Remove registry prefix if it matches common patterns
	// (e.g., "gcr.io/project/image" -> "project/image" with registry "gcr.io")
	if idx := strings.Index(image, "/"); idx > 0 {
		potentialRegistry := image[:idx]
		if strings.Contains(potentialRegistry, ".") || strings.Contains(potentialRegistry, ":") {
			registry = potentialRegistry
			imageName = image[idx+1:]
		}
	}

	// Tag is the digest prefixed with @
	tag = "@" + digest

	return registry, imageName, tag
}

func (c *aquaClient) GetScanResult(ctx context.Context, image, digest string) (*ScanResult, error) {
	// GET /api/v2/images/{registry}/{image}/{tag}
	// where tag is @sha256:...
	// If not 404, consider it scanned/passed

	registry, imageName, tag := parseImageReference(image, digest, c.config.Registry)

	// URL encode each path segment
	apiURL := fmt.Sprintf("%s/api/v2/images/%s/%s/%s",
		c.config.BaseURL,
		url.PathEscape(registry),
		url.PathEscape(imageName),
		url.PathEscape(tag),
	)

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

	return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

// triggerScanRequest is the request body for POST /api/v2/images
type triggerScanRequest struct {
	Registry string `json:"registry"`
	Image    string `json:"image"`
}

func (c *aquaClient) TriggerScan(ctx context.Context, image, digest string) (string, error) {
	// POST /api/v2/images
	// Body: {"registry": "...", "image": "imagename@sha256:..."}

	registry, imageName, _ := parseImageReference(image, digest, c.config.Registry)

	// Build the image reference with digest for the API
	// Format: imagename@sha256:...
	imageWithDigest := imageName + "@" + digest

	reqBody := triggerScanRequest{
		Registry: registry,
		Image:    imageWithDigest,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request body: %w", err)
	}

	apiURL := fmt.Sprintf("%s/api/v2/images", c.config.BaseURL)

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
		return fmt.Sprintf("%s/%s", registry, imageWithDigest), nil
	}

	// Handle other status codes
	if resp.StatusCode == http.StatusConflict {
		// Image already exists/being scanned - this is OK
		return fmt.Sprintf("%s/%s", registry, imageWithDigest), nil
	}

	return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}
