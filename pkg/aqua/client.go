package aqua

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ScanStatus represents the status returned by Aqua
type ScanStatus string

const (
	StatusNotFound  ScanStatus = "not_found"
	StatusQueued    ScanStatus = "queued"
	StatusScanning  ScanStatus = "scanning"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"

	// defaultTokenValidity is the duration (in minutes) for which the token is valid
	defaultTokenValidity = 240

	// tokenExpiryBuffer is the buffer time (in minutes) before actual expiry to refresh token
	// This accounts for clock skew and network latency
	tokenExpiryBuffer = 5
)

// tokenRequest represents the request body for token authentication
type tokenRequest struct {
	Validity         int      `json:"validity"`
	AllowedEndpoints []string `json:"allowed_endpoints"`
}

// ScanResult contains the results from Aqua
type ScanResult struct {
	Status     ScanStatus
	Image      string
	Registry   string
	Critical   int
	High       int
	Medium     int
	Low        int
	Total      int
	Disallowed bool
	ScanTime   time.Time
}

// Client interface for Aqua operations
type Client interface {
	// GetScanResult retrieves existing scan results for an image
	GetScanResult(ctx context.Context, registry, image string) (*ScanResult, error)

	// TriggerScan initiates a new scan for an image
	TriggerScan(ctx context.Context, registry, image string) error

	// GetScanStatus checks the status of a specific scan
	GetScanStatus(ctx context.Context, registry, image string) (*ScanResult, error)

	// ConvertImageRef parses an image reference and returns the Aqua registry name and image name
	ConvertImageRef(ctx context.Context, imageRef string) (registryName string, imageName string, err error)
}

// Config holds Aqua client configuration
type Config struct {
	// BaseURL is the Aqua server URL (if provided, overrides Region)
	BaseURL string

	// Region specifies the Aqua SaaS region (us, eu, singapore, sydney)
	Region string

	// APIKey for authentication
	APIKey string

	// APISecret for HMAC signature generation
	APISecret string

	// Timeout for API calls
	Timeout time.Duration

	// InsecureSkipVerify disables TLS verification (not recommended for production)
	InsecureSkipVerify bool
}

type aquaClient struct {
	config               Config
	httpClient           *http.Client
	tokenMu              sync.RWMutex
	token                string
	tokenExpiry          time.Time
	registryCacheMu      sync.RWMutex
	registryCache        map[string]string // hostname -> Aqua registry name
	registryCacheRefresh time.Time
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
		registryCache: make(map[string]string),
	}
}

// closeResponseBody drains and closes the response body to enable HTTP connection reuse.
// Errors are intentionally discarded as they cannot be meaningfully handled during cleanup.
func closeResponseBody(body io.ReadCloser) {
	// Drain any remaining content to allow connection reuse
	_, _ = io.Copy(io.Discard, body)
	// Close the body, ignoring any errors as this is cleanup code
	_ = body.Close()
}

// getBaseURL returns the base URL for the Aqua API based on region or custom URL
func (c *aquaClient) getBaseURL() string {
	if c.config.BaseURL != "" {
		return c.config.BaseURL
	}

	regions := map[string]string{
		"us":        "https://api.cloudsploit.com",
		"eu":        "https://eu-1.api.cloudsploit.com",
		"singapore": "https://asia-1.api.cloudsploit.com",
		"sydney":    "https://ap-2.api.cloudsploit.com",
	}

	baseURL, ok := regions[c.config.Region]
	if !ok {
		return regions["us"] // default to US
	}
	return baseURL
}

// authenticate generates a new bearer token using HMAC signature
func (c *aquaClient) authenticate(ctx context.Context) error {
	// Validate API secret is configured
	if c.config.APISecret == "" {
		return fmt.Errorf("API secret is required for HMAC authentication")
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	method := "POST"
	path := "/v2/tokens"

	// Create token request
	reqBody := tokenRequest{
		Validity:         defaultTokenValidity,
		AllowedEndpoints: []string{"GET", "POST", "PUT", "DELETE"},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshaling token request: %w", err)
	}
	body := string(bodyBytes)

	// Create HMAC signature
	stringToSign := timestamp + method + path + body
	h := hmac.New(sha256.New, []byte(c.config.APISecret))
	h.Write([]byte(stringToSign))
	signature := hex.EncodeToString(h.Sum(nil))

	// Make request
	apiURL := c.getBaseURL() + path
	req, err := http.NewRequestWithContext(ctx, method, apiURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating auth request: %w", err)
	}

	req.Header.Set("X-API-Key", c.config.APIKey)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing auth request: %w", err)
	}
	defer closeResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read entire response body
	bodyBytes, err2 := io.ReadAll(resp.Body)
	if err2 != nil {
		return fmt.Errorf("reading auth response: %w", err2)
	}

	var result struct {
		Status int    `json:"status"`
		Code   int    `json:"code"`
		Data   string `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return fmt.Errorf("decoding auth response: %w", err)
	}

	c.token = result.Data
	// Set expiry with buffer to prevent authentication failures at expiry boundaries
	c.tokenExpiry = time.Now().Add((defaultTokenValidity - tokenExpiryBuffer) * time.Minute)

	return nil
}

// ensureAuthenticated checks if token is valid and refreshes if needed
func (c *aquaClient) ensureAuthenticated(ctx context.Context) error {
	c.tokenMu.RLock()
	needsRefresh := c.token == "" || time.Now().After(c.tokenExpiry)
	c.tokenMu.RUnlock()

	if needsRefresh {
		c.tokenMu.Lock()
		defer c.tokenMu.Unlock()
		// Double-check after acquiring write lock
		if c.token == "" || time.Now().After(c.tokenExpiry) {
			return c.authenticate(ctx)
		}
	}
	return nil
}

// GetScanResult retrieves existing scan results for an image
func (c *aquaClient) GetScanResult(ctx context.Context, registry, image string) (*ScanResult, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Parse image reference
	_, repo, tag, err := parseImageReference(image)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}

	// URL encode parameters
	registryEncoded := url.PathEscape(registry)
	imageEncoded := url.PathEscape(repo + ":" + tag)

	// Build URL
	apiURL := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/scan_result",
		c.getBaseURL(), registryEncoded, imageEncoded)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer closeResponseBody(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return &ScanResult{
			Status:   StatusNotFound,
			Image:    image,
			Registry: registry,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read entire response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading scan result response: %w", err)
	}

	var apiResult struct {
		ImageName  string `json:"image_name"`
		Registry   string `json:"registry"`
		Disallowed bool   `json:"disallowed"`
		ScanDate   string `json:"scan_date"`  // ISO 8601 timestamp
		ScannedAt  string `json:"scanned_at"` // Alternative field name
		LastScan   string `json:"last_scan"`  // Another alternative
		CVEsCounts struct {
			Total        int     `json:"total"`
			Critical     int     `json:"critical"`
			High         int     `json:"high"`
			Medium       int     `json:"medium"`
			Low          int     `json:"low"`
			ScoreAverage float64 `json:"score_average"`
		} `json:"cves_counts"`
	}

	if err := json.Unmarshal(bodyBytes, &apiResult); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Parse scan timestamp from API response (try multiple field names)
	scanTime := time.Now() // fallback to current time if no timestamp in response
	if apiResult.ScanDate != "" {
		if t, err := time.Parse(time.RFC3339, apiResult.ScanDate); err == nil {
			scanTime = t
		}
	} else if apiResult.ScannedAt != "" {
		if t, err := time.Parse(time.RFC3339, apiResult.ScannedAt); err == nil {
			scanTime = t
		}
	} else if apiResult.LastScan != "" {
		if t, err := time.Parse(time.RFC3339, apiResult.LastScan); err == nil {
			scanTime = t
		}
	}

	result := &ScanResult{
		Status:     StatusCompleted,
		Image:      image,
		Registry:   registry,
		Critical:   apiResult.CVEsCounts.Critical,
		High:       apiResult.CVEsCounts.High,
		Medium:     apiResult.CVEsCounts.Medium,
		Low:        apiResult.CVEsCounts.Low,
		Total:      apiResult.CVEsCounts.Total,
		Disallowed: apiResult.Disallowed,
		ScanTime:   scanTime,
	}

	return result, nil
}

// TriggerScan initiates a new scan for an image
func (c *aquaClient) TriggerScan(ctx context.Context, registry, image string) error {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Parse image reference
	_, repo, tag, err := parseImageReference(image)
	if err != nil {
		return fmt.Errorf("parsing image reference: %w", err)
	}

	// URL encode parameters
	registryEncoded := url.PathEscape(registry)
	imageEncoded := url.PathEscape(repo + ":" + tag)

	// Build URL
	apiURL := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/scan",
		c.getBaseURL(), registryEncoded, imageEncoded)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer closeResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("scan trigger failed with status: %d", resp.StatusCode)
	}

	return nil
}

// GetScanStatus checks the status of a specific scan
func (c *aquaClient) GetScanStatus(ctx context.Context, registry, image string) (*ScanResult, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Parse image reference
	_, repo, tag, err := parseImageReference(image)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}

	// URL encode parameters
	registryEncoded := url.PathEscape(registry)
	imageEncoded := url.PathEscape(repo + ":" + tag)

	// Build URL
	apiURL := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/status",
		c.getBaseURL(), registryEncoded, imageEncoded)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer closeResponseBody(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return &ScanResult{
			Status:   StatusNotFound,
			Image:    image,
			Registry: registry,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read entire response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading scan status response: %w", err)
	}

	var apiResult struct {
		Status string `json:"status"`
	}

	if err := json.Unmarshal(bodyBytes, &apiResult); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Map Aqua status to our status constants
	var status ScanStatus
	switch apiResult.Status {
	case "Scanned":
		status = StatusCompleted
	case "Pending":
		status = StatusQueued
	case "In Progress":
		status = StatusScanning
	case "Fail":
		status = StatusFailed
	default:
		status = StatusNotFound
	}

	result := &ScanResult{
		Status:   status,
		Image:    image,
		Registry: registry,
	}

	return result, nil
}

// parseImageReference parses an image reference into registry, repository, and tag components
func parseImageReference(imageRef string) (registry, repository, tag string, err error) {
	// Remove digest if present
	if strings.Contains(imageRef, "@") {
		parts := strings.Split(imageRef, "@")
		imageRef = parts[0]
	}

	// Handle tag
	tagIdx := strings.LastIndex(imageRef, ":")
	hasPort := false

	// Check if the colon is part of a port number (e.g., registry.io:5000)
	if tagIdx > 0 {
		beforeColon := imageRef[:tagIdx]
		if strings.Contains(beforeColon, "/") {
			// Colon is after a slash, so it's a tag
			tag = imageRef[tagIdx+1:]
			imageRef = imageRef[:tagIdx]
		} else if strings.Contains(beforeColon, ".") {
			// Colon is in the domain, so it's a port
			hasPort = true
			tag = "latest"
		} else {
			// Single name with colon, it's a tag
			tag = imageRef[tagIdx+1:]
			imageRef = imageRef[:tagIdx]
		}
	} else {
		tag = "latest"
	}

	// Handle registry and repository
	slashIdx := strings.Index(imageRef, "/")
	if slashIdx > 0 {
		registryPart := imageRef[:slashIdx]
		// Check if it looks like a registry (has . or :)
		if strings.Contains(registryPart, ".") || (hasPort && strings.Contains(registryPart, ":")) {
			registry = registryPart
			repository = imageRef[slashIdx+1:]
		} else {
			// It's a Docker Hub image with namespace (e.g., library/nginx)
			registry = "docker.io"
			repository = imageRef
		}
	} else {
		// No slash, it's a Docker Hub image
		registry = "docker.io"
		repository = imageRef
	}

	return registry, repository, tag, nil
}

// registryListResponse represents the response from /registries API
type registryListResponse struct {
	Count    int `json:"count"`
	Page     int `json:"page"`
	PageSize int `json:"pagesize"`
	Result   []struct {
		Name     string   `json:"name"`
		Prefixes []string `json:"prefixes"`
	} `json:"result"`
}

// RefreshRegistryCache fetches all registries from Aqua API and populates the cache
func (c *aquaClient) RefreshRegistryCache(ctx context.Context) error {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	newCache := make(map[string]string)
	page := 1
	pageSize := 100

	for {
		// Build URL with pagination
		apiURL := fmt.Sprintf("%s/api/v2/registries?page=%d&pagesize=%d",
			c.getBaseURL(), page, pageSize)

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return fmt.Errorf("creating registries request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("executing registries request: %w", err)
		}
		defer closeResponseBody(resp.Body)

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("registries API failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}

		// Read entire response body
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading registries response: %w", err)
		}

		var response registryListResponse
		if err := json.Unmarshal(bodyBytes, &response); err != nil {
			return fmt.Errorf("decoding registries response: %w", err)
		}

		// Populate cache with hostname -> registry name mappings
		for _, reg := range response.Result {
			for _, prefix := range reg.Prefixes {
				// Normalize the prefix (remove protocol if present)
				prefix = strings.TrimPrefix(prefix, "https://")
				prefix = strings.TrimPrefix(prefix, "http://")
				newCache[prefix] = reg.Name
			}
		}

		// Check if we have more pages
		if len(response.Result) < pageSize {
			break
		}
		page++
	}

	// Update cache atomically
	c.registryCacheMu.Lock()
	c.registryCache = newCache
	c.registryCacheRefresh = time.Now()
	c.registryCacheMu.Unlock()

	return nil
}

// GetRegistryName returns the Aqua registry name for a given registry hostname
// It automatically refreshes the cache if needed (older than 1 hour or not found)
func (c *aquaClient) GetRegistryName(ctx context.Context, hostname string) (string, error) {
	// Normalize hostname
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")

	// Check if cache needs refresh (older than 1 hour)
	c.registryCacheMu.RLock()
	cacheAge := time.Since(c.registryCacheRefresh)
	registryName, found := c.registryCache[hostname]
	c.registryCacheMu.RUnlock()

	// Refresh cache if it's older than 1 hour
	if cacheAge > time.Hour {
		if err := c.RefreshRegistryCache(ctx); err != nil {
			return "", fmt.Errorf("refreshing registry cache: %w", err)
		}

		// Try lookup again after refresh
		c.registryCacheMu.RLock()
		registryName, found = c.registryCache[hostname]
		c.registryCacheMu.RUnlock()
	}

	// If not found, refresh cache and try again
	if !found {
		if err := c.RefreshRegistryCache(ctx); err != nil {
			return "", fmt.Errorf("refreshing registry cache: %w", err)
		}

		c.registryCacheMu.RLock()
		registryName, found = c.registryCache[hostname]
		c.registryCacheMu.RUnlock()

		if !found {
			return "", fmt.Errorf("registry not found in Aqua: %s", hostname)
		}
	}

	return registryName, nil
}

// ConvertImageRef parses an image reference and returns the Aqua registry name and image name
// Example: "docker.io/library/python:3.12.12" -> ("Docker Hub", "library/python:3.12.12")
func (c *aquaClient) ConvertImageRef(ctx context.Context, imageRef string) (registryName string, imageName string, err error) {
	// Parse the image reference
	hostname, repository, tag, err := parseImageReference(imageRef)
	if err != nil {
		return "", "", fmt.Errorf("parsing image reference: %w", err)
	}

	// Get the Aqua registry name for this hostname
	registryName, err = c.GetRegistryName(ctx, hostname)
	if err != nil {
		return "", "", fmt.Errorf("looking up registry name: %w", err)
	}

	// Construct the image name (repository:tag)
	imageName = repository + ":" + tag

	return registryName, imageName, nil
}
