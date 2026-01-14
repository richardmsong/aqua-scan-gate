package aqua

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// DefaultAuthURL is the default authentication endpoint (US region)
const DefaultAuthURL = "https://api.cloudsploit.com"

// AuthConfig holds authentication configuration
type AuthConfig struct {
	// APIKey is the API key for authentication (used in X-API-Key header)
	APIKey string

	// HMACSecret is used for HMAC256 request signing
	HMACSecret string

	// AuthURL is the regional authentication endpoint URL
	// Regional endpoints:
	//   - US: https://api.cloudsploit.com (default)
	//   - EU: https://eu-1.api.cloudsploit.com
	//   - Singapore: https://asia-1.api.cloudsploit.com
	//   - Sydney: https://ap-2.api.cloudsploit.com
	// If empty, defaults to US region (https://api.cloudsploit.com)
	AuthURL string

	// TokenValidity is the token validity in minutes (default: 240)
	TokenValidity int
}

// tokenResponse is the response from POST /v2/tokens
type tokenResponse struct {
	Status int    `json:"status"`
	Code   int    `json:"code"`
	Data   string `json:"data"`
}

// tokenRequest is the request body for POST /v2/tokens
type tokenRequest struct {
	Validity         int      `json:"validity"`
	AllowedEndpoints []string `json:"allowed_endpoints"`
}

// TokenManager handles token acquisition and request signing
type TokenManager struct {
	authURL    string
	config     AuthConfig
	httpClient *http.Client
	verbose    bool

	// Token cache
	mu         sync.RWMutex
	token      string
	tokenExpAt time.Time
}

// NewTokenManager creates a new token manager
// If AuthURL is empty in config, it defaults to the US region (https://api.cloudsploit.com)
func NewTokenManager(baseURL string, config AuthConfig, httpClient *http.Client, verbose bool) *TokenManager {
	if config.TokenValidity == 0 {
		config.TokenValidity = 240 // Default 240 minutes
	}
	// Use AuthURL if provided, otherwise default to US region
	authURL := config.AuthURL
	if authURL == "" {
		authURL = DefaultAuthURL
	}
	return &TokenManager{
		authURL:    authURL,
		config:     config,
		httpClient: httpClient,
		verbose:    verbose,
	}
}

// GetToken returns a valid bearer token, fetching a new one if necessary
// The token is obtained by making a HMAC-signed request to POST /v2/tokens
func (tm *TokenManager) GetToken(ctx context.Context) (string, error) {
	// Check if we have a valid cached token
	tm.mu.RLock()
	if tm.token != "" && time.Now().Before(tm.tokenExpAt) {
		token := tm.token
		tm.mu.RUnlock()
		if tm.verbose {
			masked := token[:min(6, len(token))] + "..."
			log.Printf("[AUTH] GetToken: using cached token %s (expires in %v)", masked, time.Until(tm.tokenExpAt))
		}
		return token, nil
	}
	tm.mu.RUnlock()

	// Need to fetch a new token
	return tm.fetchToken(ctx)
}

// fetchToken fetches a new bearer token from the Aqua API
func (tm *TokenManager) fetchToken(ctx context.Context) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after acquiring write lock
	if tm.token != "" && time.Now().Before(tm.tokenExpAt) {
		return tm.token, nil
	}

	// Build request body
	reqBody := tokenRequest{
		Validity:         tm.config.TokenValidity,
		AllowedEndpoints: []string{"GET", "POST", "PUT", "DELETE"},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling token request: %w", err)
	}

	// Build the request using the auth URL (regional endpoint)
	url := tm.authURL + "/v2/tokens"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}

	// Generate timestamp
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Build string to sign: timestamp + method + path + body
	stringToSign := fmt.Sprintf("%s%s%s%s",
		timestamp,
		"POST",
		"/v2/tokens",
		string(bodyBytes),
	)

	// Compute HMAC256 signature
	signature := computeHMAC256(stringToSign, tm.config.HMACSecret)

	if tm.verbose {
		log.Printf("[AUTH] fetchToken: requesting new token from %s", url)
		log.Printf("[AUTH] fetchToken: timestamp=%s", timestamp)
		log.Printf("[AUTH] fetchToken: signature=%s... (len=%d)", signature[:min(16, len(signature))], len(signature))
	}

	// Set headers per Aqua API spec
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", tm.config.APIKey)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)

	// Execute request
	resp, err := tm.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing token request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Read response body
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var tokenResp tokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}

	if tokenResp.Data == "" {
		return "", fmt.Errorf("empty token in response: %s", string(respBody))
	}

	// Cache the token with expiration (use 90% of validity to refresh early)
	tm.token = tokenResp.Data
	tm.tokenExpAt = time.Now().Add(time.Duration(float64(tm.config.TokenValidity)*0.9) * time.Minute)

	if tm.verbose {
		masked := tm.token[:min(6, len(tm.token))] + "..."
		log.Printf("[AUTH] fetchToken: obtained token %s (expires at %v)", masked, tm.tokenExpAt)
	}

	return tm.token, nil
}

// computeHMAC256 computes HMAC-SHA256 signature
func computeHMAC256(message, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateHMACSignature validates an incoming HMAC signature
// This can be useful for webhook validation
func ValidateHMACSignature(message, signature, secret string) bool {
	expectedSig := computeHMAC256(message, secret)
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}

// FetchToken is a convenience function to fetch an access token using the provided configuration.
// This is useful for CLI tools that need to output a token for debugging or scripting purposes.
// The token can be used as a Bearer token for Aqua API requests.
func FetchToken(ctx context.Context, config AuthConfig, verbose bool) (string, error) {
	if config.APIKey == "" {
		return "", fmt.Errorf("API key is required")
	}
	if config.HMACSecret == "" {
		return "", fmt.Errorf("HMAC secret is required")
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	tm := NewTokenManager("", config, httpClient, verbose)
	return tm.GetToken(ctx)
}
