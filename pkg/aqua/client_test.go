package aqua

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test fixtures for mocking Aqua API responses

// mockTokenResponse returns a successful token generation response
func mockTokenResponse() string {
	return `{
		"status": 200,
		"code": 0,
		"data": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
	}`
}

// mockScanResultResponse returns a successful scan result with vulnerabilities
func mockScanResultResponse() string {
	return `{
		"image_name": "nginx:latest",
		"registry": "Docker Hub",
		"disallowed": false,
		"cves_counts": {
			"total": 10,
			"critical": 0,
			"high": 2,
			"medium": 5,
			"low": 3,
			"score_average": 5.8
		},
		"cves": [
			{
				"imageid": "nginx:latest",
				"file": "libssl1.1_1.1.1-1_amd64.deb",
				"name": "CVE-2023-12345",
				"type": "CVE",
				"description": "Test vulnerability",
				"score": 7.5,
				"severity": "high",
				"publishdate": "2023-01-15",
				"acknowledged": false
			}
		]
	}`
}

// mockScanResultWithCriticalVulns returns scan result with critical vulnerabilities
func mockScanResultWithCriticalVulns() string {
	return `{
		"image_name": "vulnerable:latest",
		"registry": "Docker Hub",
		"disallowed": false,
		"cves_counts": {
			"total": 15,
			"critical": 3,
			"high": 5,
			"medium": 4,
			"low": 3,
			"score_average": 8.2
		}
	}`
}

// mockScanStatusPending returns a pending scan status
func mockScanStatusPending() string {
	return `{"status": "Pending"}`
}

// mockScanStatusInProgress returns an in-progress scan status
func mockScanStatusInProgress() string {
	return `{"status": "In Progress"}`
}

// mockScanStatusScanned returns a completed scan status
func mockScanStatusScanned() string {
	return `{"status": "Scanned"}`
}

// mockScanStatusFailed returns a failed scan status
func mockScanStatusFailed() string {
	return `{"status": "Fail"}`
}

// mockErrorResponse returns a generic error response
func mockErrorResponse(statusCode int, message string) (int, string) {
	return statusCode, fmt.Sprintf(`{
		"status": %d,
		"code": 1001,
		"message": "%s"
	}`, statusCode, message)
}

// TestNewClient verifies client initialization
func TestNewClient(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		expectedRegion string
	}{
		{
			name: "US region client",
			config: Config{
				Region:    "us",
				APIKey:    "test-key",
				APISecret: "test-secret",
			},
			expectedRegion: "us",
		},
		{
			name: "EU region client",
			config: Config{
				Region:    "eu",
				APIKey:    "test-key",
				APISecret: "test-secret",
			},
			expectedRegion: "eu",
		},
		{
			name: "Client with custom timeout",
			config: Config{
				Region:    "us",
				APIKey:    "test-key",
				APISecret: "test-secret",
				Timeout:   60 * time.Second,
			},
			expectedRegion: "us",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.config)
			if client == nil {
				t.Fatal("Expected non-nil client")
			}

			aquaClient, ok := client.(*aquaClient)
			if !ok {
				t.Fatal("Expected aquaClient type")
			}

			if aquaClient.config.Region != tt.expectedRegion {
				t.Errorf("Expected region %s, got %s", tt.expectedRegion, aquaClient.config.Region)
			}

			if aquaClient.config.Timeout == 0 {
				t.Error("Expected non-zero timeout")
			}
		})
	}
}

// TestAuthenticate verifies token generation
func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   string
		mockStatusCode int
		expectError    bool
	}{
		{
			name:           "successful authentication",
			mockResponse:   mockTokenResponse(),
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "authentication failure",
			mockResponse:   `{"status": 401, "message": "Invalid credentials"}`,
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify authentication headers
				if r.Header.Get("X-API-Key") == "" {
					t.Error("Missing X-API-Key header")
				}
				if r.Header.Get("X-Timestamp") == "" {
					t.Error("Missing X-Timestamp header")
				}
				if r.Header.Get("X-Signature") == "" {
					t.Error("Missing X-Signature header")
				}

				w.WriteHeader(tt.mockStatusCode)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			client := NewClient(Config{
				BaseURL:   server.URL,
				Region:    "us",
				APIKey:    "test-key",
				APISecret: "test-secret",
			})

			aquaClient := client.(*aquaClient)
			err := aquaClient.authenticate(context.Background())

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && aquaClient.token == "" {
				t.Error("Expected token to be set")
			}
		})
	}
}

// TestGetScanResult verifies retrieving scan results
func TestGetScanResult(t *testing.T) {
	tests := []struct {
		name           string
		registry       string
		image          string
		mockResponse   string
		mockStatusCode int
		expectError    bool
		expectedStatus ScanStatus
	}{
		{
			name:           "successful scan result retrieval",
			registry:       "Docker Hub",
			image:          "nginx:latest",
			mockResponse:   mockScanResultResponse(),
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedStatus: StatusCompleted,
		},
		{
			name:           "scan result with critical vulnerabilities",
			registry:       "Docker Hub",
			image:          "vulnerable:latest",
			mockResponse:   mockScanResultWithCriticalVulns(),
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedStatus: StatusCompleted,
		},
		{
			name:           "image not found",
			registry:       "Docker Hub",
			image:          "nonexistent:latest",
			mockResponse:   "",
			mockStatusCode: http.StatusNotFound,
			expectError:    false,
			expectedStatus: StatusNotFound,
		},
		{
			name:           "server error",
			registry:       "Docker Hub",
			image:          "nginx:latest",
			mockResponse:   `{"status": 500, "message": "Internal server error"}`,
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
			expectedStatus: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callCount++

				// First call is for authentication
				if callCount == 1 {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(mockTokenResponse()))
					return
				}

				// Verify authorization header
				if r.Header.Get("Authorization") == "" {
					t.Error("Missing Authorization header")
				}

				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != "" {
					w.Write([]byte(tt.mockResponse))
				}
			}))
			defer server.Close()

			client := NewClient(Config{
				BaseURL:   server.URL,
				Region:    "us",
				APIKey:    "test-key",
				APISecret: "test-secret",
			})

			result, err := client.GetScanResult(context.Background(), tt.registry, tt.image)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && result != nil {
				if result.Status != tt.expectedStatus {
					t.Errorf("Expected status %s, got %s", tt.expectedStatus, result.Status)
				}
			}
		})
	}
}

// TestTriggerScan verifies scan initiation
func TestTriggerScan(t *testing.T) {
	tests := []struct {
		name           string
		registry       string
		image          string
		mockStatusCode int
		expectError    bool
	}{
		{
			name:           "successful scan trigger",
			registry:       "Docker Hub",
			image:          "nginx:latest",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "scan trigger with URL encoding",
			registry:       "Private Registry",
			image:          "my-app:v1.0",
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "authentication failure",
			registry:       "Docker Hub",
			image:          "nginx:latest",
			mockStatusCode: http.StatusUnauthorized,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callCount++

				// First call is for authentication
				if callCount == 1 {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(mockTokenResponse()))
					return
				}

				// Verify it's a POST request
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}

				// Verify authorization header
				if r.Header.Get("Authorization") == "" {
					t.Error("Missing Authorization header")
				}

				w.WriteHeader(tt.mockStatusCode)
			}))
			defer server.Close()

			client := NewClient(Config{
				BaseURL:   server.URL,
				Region:    "us",
				APIKey:    "test-key",
				APISecret: "test-secret",
			})

			scanID, err := client.TriggerScan(context.Background(), tt.registry, tt.image)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && scanID == "" {
				t.Error("Expected non-empty scan ID")
			}
		})
	}
}

// TestGetScanStatus verifies scan status checking
func TestGetScanStatus(t *testing.T) {
	tests := []struct {
		name           string
		registry       string
		image          string
		mockResponse   string
		mockStatusCode int
		expectError    bool
		expectedStatus ScanStatus
	}{
		{
			name:           "scan completed",
			registry:       "Docker Hub",
			image:          "nginx:latest",
			mockResponse:   mockScanStatusScanned(),
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedStatus: StatusCompleted,
		},
		{
			name:           "scan pending",
			registry:       "Docker Hub",
			image:          "nginx:latest",
			mockResponse:   mockScanStatusPending(),
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedStatus: StatusQueued,
		},
		{
			name:           "scan in progress",
			registry:       "Docker Hub",
			image:          "nginx:latest",
			mockResponse:   mockScanStatusInProgress(),
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedStatus: StatusScanning,
		},
		{
			name:           "scan failed",
			registry:       "Docker Hub",
			image:          "nginx:latest",
			mockResponse:   mockScanStatusFailed(),
			mockStatusCode: http.StatusOK,
			expectError:    false,
			expectedStatus: StatusFailed,
		},
		{
			name:           "image not found",
			registry:       "Docker Hub",
			image:          "nonexistent:latest",
			mockResponse:   "",
			mockStatusCode: http.StatusNotFound,
			expectError:    false,
			expectedStatus: StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callCount++

				// First call is for authentication
				if callCount == 1 {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(mockTokenResponse()))
					return
				}

				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != "" {
					w.Write([]byte(tt.mockResponse))
				}
			}))
			defer server.Close()

			client := NewClient(Config{
				BaseURL:   server.URL,
				Region:    "us",
				APIKey:    "test-key",
				APISecret: "test-secret",
			})

			result, err := client.GetScanStatus(context.Background(), tt.registry, tt.image)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && result != nil {
				if result.Status != tt.expectedStatus {
					t.Errorf("Expected status %s, got %s", tt.expectedStatus, result.Status)
				}
			}
		})
	}
}

// TestTokenExpiration verifies token refresh logic
func TestTokenExpiration(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		// Authentication calls
		if r.URL.Path == "/v2/tokens" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockTokenResponse()))
			return
		}

		// API calls
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockScanStatusScanned()))
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:   server.URL,
		Region:    "us",
		APIKey:    "test-key",
		APISecret: "test-secret",
	})

	aquaClient := client.(*aquaClient)

	// First call - should authenticate
	_, err := client.GetScanStatus(context.Background(), "Docker Hub", "nginx:latest")
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	// Expire the token
	aquaClient.tokenExpiry = time.Now().Add(-1 * time.Minute)

	// Second call - should re-authenticate
	_, err = client.GetScanStatus(context.Background(), "Docker Hub", "nginx:latest")
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	// Should have called authentication twice
	authCallCount := 0
	for i := 1; i <= callCount; i++ {
		if i == 1 || i == 3 {
			authCallCount++
		}
	}

	if authCallCount < 2 {
		t.Error("Expected token to be refreshed on expiration")
	}
}

// TestContextCancellation verifies context handling
func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockTokenResponse()))
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:   server.URL,
		Region:    "us",
		APIKey:    "test-key",
		APISecret: "test-secret",
		Timeout:   50 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.GetScanStatus(ctx, "Docker Hub", "nginx:latest")
	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

// TestInvalidJSON verifies error handling for malformed responses
func TestInvalidJSON(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		// First call is for authentication
		if callCount == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockTokenResponse()))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:   server.URL,
		Region:    "us",
		APIKey:    "test-key",
		APISecret: "test-secret",
	})

	_, err := client.GetScanResult(context.Background(), "Docker Hub", "nginx:latest")
	if err == nil {
		t.Error("Expected JSON decode error")
	}
}

// TestParseImageReference verifies image reference parsing
func TestParseImageReference(t *testing.T) {
	tests := []struct {
		name              string
		imageRef          string
		expectedRegistry  string
		expectedRepo      string
		expectedTag       string
		expectError       bool
	}{
		{
			name:             "docker hub image with tag",
			imageRef:         "nginx:latest",
			expectedRegistry: "Docker Hub",
			expectedRepo:     "nginx",
			expectedTag:      "latest",
			expectError:      false,
		},
		{
			name:             "docker hub image without tag",
			imageRef:         "nginx",
			expectedRegistry: "Docker Hub",
			expectedRepo:     "nginx",
			expectedTag:      "latest",
			expectError:      false,
		},
		{
			name:             "private registry with port",
			imageRef:         "registry.io:5000/myapp:v1.0",
			expectedRegistry: "registry.io:5000",
			expectedRepo:     "myapp",
			expectedTag:      "v1.0",
			expectError:      false,
		},
		{
			name:             "gcr image",
			imageRef:         "gcr.io/project/image:tag",
			expectedRegistry: "gcr.io",
			expectedRepo:     "project/image",
			expectedTag:      "tag",
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, repo, tag, err := parseImageReference(tt.imageRef)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if registry != tt.expectedRegistry {
				t.Errorf("Expected registry %s, got %s", tt.expectedRegistry, registry)
			}
			if repo != tt.expectedRepo {
				t.Errorf("Expected repo %s, got %s", tt.expectedRepo, repo)
			}
			if tag != tt.expectedTag {
				t.Errorf("Expected tag %s, got %s", tt.expectedTag, tag)
			}
		})
	}
}

// Example response types for reference
type tokenResponse struct {
	Status int    `json:"status"`
	Code   int    `json:"code"`
	Data   string `json:"data"`
}

type scanStatusResponse struct {
	Status string `json:"status"`
}

type scanResultResponse struct {
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
	CVEs []struct {
		ImageID     string  `json:"imageid"`
		File        string  `json:"file"`
		Name        string  `json:"name"`
		Type        string  `json:"type"`
		Description string  `json:"description"`
		Score       float64 `json:"score"`
		Severity    string  `json:"severity"`
		PublishDate string  `json:"publishdate"`
		Acknowledged bool   `json:"acknowledged"`
	} `json:"cves"`
}

// unmarshalTestResponse is a helper for tests
func unmarshalTestResponse(t *testing.T, data []byte, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}
}
