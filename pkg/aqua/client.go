package aqua

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	StatusNotFound  ScanStatus = "not_found"
	StatusQueued    ScanStatus = "queued"
	StatusScanning  ScanStatus = "scanning"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
)

// ScanResult contains the results from Aqua
type ScanResult struct {
	ScanID           string
	Status           ScanStatus
	Image            string
	Registry         string
	Digest           string
	Critical         int
	High             int
	Medium           int
	Low              int
	Total            int
	CompliancePassed bool
	Disallowed       bool
	ScanTime         time.Time
}

// Client interface for Aqua operations
type Client interface {
	// GetScanResult retrieves existing scan results for an image
	GetScanResult(ctx context.Context, registry, image string) (*ScanResult, error)

	// TriggerScan initiates a new scan for an image
	TriggerScan(ctx context.Context, registry, image string) (string, error)

	// GetScanStatus checks the status of a specific scan
	GetScanStatus(ctx context.Context, registry, image string) (*ScanResult, error)
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
	config      Config
	httpClient  *http.Client
	token       string
	tokenExpiry time.Time
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
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	method := "POST"
	path := "/v2/tokens"
	body := `{"validity":240,"allowed_endpoints":["GET","POST","PUT","DELETE"]}`

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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Status int    `json:"status"`
		Code   int    `json:"code"`
		Data   string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding auth response: %w", err)
	}

	c.token = result.Data
	c.tokenExpiry = time.Now().Add(240 * time.Minute)

	return nil
}

// ensureAuthenticated checks if token is valid and refreshes if needed
func (c *aquaClient) ensureAuthenticated(ctx context.Context) error {
	if c.token == "" || time.Now().After(c.tokenExpiry) {
		return c.authenticate(ctx)
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
	defer resp.Body.Close()

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

	var apiResult struct {
		ImageName  string `json:"image_name"`
		Registry   string `json:"registry"`
		Disallowed bool   `json:"disallowed"`
		CVEsCounts struct {
			Total        int     `json:"total"`
			Critical     int     `json:"critical"`
			High         int     `json:"high"`
			Medium       int     `json:"medium"`
			Low          int     `json:"low"`
			ScoreAverage float64 `json:"score_average"`
		} `json:"cves_counts"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResult); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	result := &ScanResult{
		Status:           StatusCompleted,
		Image:            image,
		Registry:         registry,
		Critical:         apiResult.CVEsCounts.Critical,
		High:             apiResult.CVEsCounts.High,
		Medium:           apiResult.CVEsCounts.Medium,
		Low:              apiResult.CVEsCounts.Low,
		Total:            apiResult.CVEsCounts.Total,
		Disallowed:       apiResult.Disallowed,
		CompliancePassed: !apiResult.Disallowed && apiResult.CVEsCounts.Critical == 0,
		ScanTime:         time.Now(),
	}

	return result, nil
}

// TriggerScan initiates a new scan for an image
func (c *aquaClient) TriggerScan(ctx context.Context, registry, image string) (string, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}

	// Parse image reference
	_, repo, tag, err := parseImageReference(image)
	if err != nil {
		return "", fmt.Errorf("parsing image reference: %w", err)
	}

	// URL encode parameters
	registryEncoded := url.PathEscape(registry)
	imageEncoded := url.PathEscape(repo + ":" + tag)

	// Build URL
	apiURL := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/scan",
		c.getBaseURL(), registryEncoded, imageEncoded)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("scan trigger failed with status: %d", resp.StatusCode)
	}

	// Generate a scan ID for tracking (combination of registry, image, and timestamp)
	scanID := fmt.Sprintf("%s/%s-%d", registry, image, time.Now().Unix())

	return scanID, nil
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
	defer resp.Body.Close()

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

	var apiResult struct {
		Status string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResult); err != nil {
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
			registry = "Docker Hub"
			repository = imageRef
		}
	} else {
		// No slash, it's a Docker Hub image
		registry = "Docker Hub"
		repository = imageRef
	}

	return registry, repository, tag, nil
}
