# Aqua Security API Reference

This document provides comprehensive information about the Aqua Security API endpoints used by the Aqua Scan Gate Controller. This information was gathered from the official Aqua Security SaaS API documentation.

## Table of Contents

1. [Authentication](#authentication)
2. [Image Scanning APIs (v1)](#image-scanning-apis-v1)
3. [Scan Queue Management (v1)](#scan-queue-management-v1)
4. [Images API (v2)](#images-api-v2)
5. [Implementation Guide](#implementation-guide)
6. [Common Response Formats](#common-response-formats)

---

## Authentication

### Overview

Aqua Platform SaaS Edition uses **HMAC256 signature-based authentication** to generate Bearer tokens for API access.

### Regional Endpoints

The Authentication API endpoint depends on your geographical region:

| Region    | Authentication Endpoint                    |
|-----------|--------------------------------------------|
| US        | `https://api.cloudsploit.com/`            |
| EU        | `https://eu-1.api.cloudsploit.com/`       |
| Singapore | `https://asia-1.api.cloudsploit.com/`     |
| Sydney    | `https://ap-2.api.cloudsploit.com/`       |

### Generate Authentication Token

**Endpoint**: `POST /v2/tokens`

**Method**: `POST`

**Required Headers**:
- `X-API-Key`: Your API key (obtained from Aqua console)
- `X-Timestamp`: Current Unix timestamp in seconds
- `X-Signature`: HMAC256 signature (see below)
- `Content-Type`: `application/json`

**POST Body**:
```json
{
  "validity": 240,
  "allowed_endpoints": [
    "GET",
    "POST",
    "PUT",
    "DELETE"
  ]
}
```

**Fields**:
- `validity`: Token lifetime in minutes (1-1500)
- `allowed_endpoints`: HTTP methods the token can access

### HMAC256 Signature Creation

The signature is generated using the HMAC256 algorithm:

**String to Sign**: `timestamp + method + path + body`

**Example** (using Go):
```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"
)

func createSignature(secret, method, path, body string) string {
    timestamp := fmt.Sprintf("%d", time.Now().Unix())
    stringToSign := timestamp + method + path + body

    h := hmac.New(sha256.New, []byte(secret))
    h.Write([]byte(stringToSign))
    signature := hex.EncodeToString(h.Sum(nil))

    return signature
}
```

**Example** (shell script):
```bash
API_KEY="your-api-key"
API_SECRET="your-api-secret"
TIMESTAMP=$(date -u +%s)
ENDPOINT="https://api.cloudsploit.com/v2/tokens"
METHOD="POST"

POST_BODY='{"validity":240,"allowed_endpoints":["GET","POST"]}'

# Create signature
STRING_TO_SIGN="$TIMESTAMP$METHOD/v2/tokens$POST_BODY"
SIGNATURE=$(echo -n "$STRING_TO_SIGN" | openssl dgst -sha256 -hmac "$API_SECRET" -hex | sed 's/.*= //g')

# Request token
RESPONSE=$(curl -s -X $METHOD $ENDPOINT \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Signature: $SIGNATURE" \
  -d "$POST_BODY")

# Extract token
TOKEN=$(echo $RESPONSE | jq -r '.data')
```

### Response Format

```json
{
  "status": 200,
  "code": 0,
  "data": "<bearer-token>"
}
```

### Using the Bearer Token

For all subsequent API requests, include the token in the Authorization header:

```
Authorization: Bearer <token>
```

---

## Image Scanning APIs (v1)

These REST API endpoints initiate image scanning and retrieve scan status and results.

### 1. Start Image Scan

Triggers a scan for a specified image in a registry.

**Endpoint**: `POST /api/v1/scanner/registry/{registry}/image/{image}/scan`

**Authentication**: Bearer token or basic auth

**URL Parameters**:
- `{registry}`: Registry name (URL-encoded, e.g., `Docker%20Hub`)
- `{image}`: Image name in format `repository:tag` (defaults to `latest` if no tag)

**Request Body** (optional):
```json
{
  "webhook_url": "https://your-webhook-endpoint.com/callback"
}
```

If a webhook URL is provided, scan results will be POSTed to this URL asynchronously.

**Requirements**:
- Registry must already be defined in Aqua Server
- User must have "Edit" permission in Assets > Images
- Image scanning also registers the image if not already registered

**Example Request**:
```bash
curl -X POST \
  "https://api.cloudsploit.com/api/v1/scanner/registry/Docker%20Hub/image/nginx:latest/scan" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://my-app.com/webhook"}'
```

**Response**: `200 OK` (scan initiated)

### 2. Get Scan Status

Retrieves the current status of an image scan.

**Endpoint**: `GET /api/v1/scanner/registry/{registry}/image/{image}/status`

**Authentication**: Bearer token or basic auth

**URL Parameters**:
- `{registry}`: Registry name (URL-encoded)
- `{image}`: Image name in format `repository:tag`

**Response**:
```json
{
  "status": "Scanned"
}
```

**Possible Status Values**:
- `Scanned`: Scan completed successfully
- `Pending`: Scan queued but not started
- `In Progress`: Scan currently running
- `Fail`: Scan failed

**Example Request**:
```bash
curl -X GET \
  "https://api.cloudsploit.com/api/v1/scanner/registry/Docker%20Hub/image/nginx:latest/status" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/json"
```

### 3. Get Scan Results

Retrieves detailed scan results for an image.

**Endpoint**: `GET /api/v1/scanner/registry/{registry}/image/{image}/scan_result`

**Authentication**: Bearer token or basic auth

**URL Parameters**:
- `{registry}`: Registry name (URL-encoded)
- `{image}`: Image name in format `repository:tag`

**Response**:
```json
{
  "image_name": "nginx:latest",
  "registry": "Docker Hub",
  "disallowed": false,
  "cves_counts": {
    "total": 10,
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
      "description": "Vulnerability description here",
      "score": 7.5,
      "severity": "high",
      "publishdate": "2023-01-15",
      "acknowledged": false
    }
  ]
}
```

**Example Request**:
```bash
curl -X GET \
  "https://api.cloudsploit.com/api/v1/scanner/registry/Docker%20Hub/image/nginx:latest/scan_result" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/json"
```

### 4. Get Image Vulnerability Report (CSV)

Downloads vulnerability report in CSV format.

**Endpoint**: `GET /api/v1/cves/report/csv`

**Authentication**: Bearer token or basic auth

**Response**: CSV file with all CVEs

---

## Scan Queue Management (v1)

APIs for managing the image scan queue.

### 1. List Scan Jobs

Lists all jobs in the scan queue with pagination and filtering.

**Endpoint**: `GET /api/v1/scanqueue`

**Authentication**: Bearer token or basic auth

**Query Parameters**:
- `page_size` (integer, optional): Maximum jobs to return (default: 50)
- `page` (integer, optional): Page number (default: 1)
- `order_by` (string, optional): Sort order, format: `<column> <direction>` (e.g., `created desc`)
- `statuses` (array, optional): Filter by status (repeatable parameter)

**Status Values**:
- `pending`: Job not started
- `in_progress`: Job currently processing
- `finished`: Job completed successfully
- `failed`: Job failed

**Response**:
```json
{
  "count": 6,
  "page": 1,
  "pagesize": 50,
  "result": [
    {
      "registry": "Docker Hub",
      "image": "nginx:latest",
      "created": "2024-01-09T10:15:43.319593Z",
      "last_updated": "2024-01-09T10:15:53.517330Z",
      "status": "finished",
      "assigned_scanner": "scanner-pod-123"
    }
  ]
}
```

**Example Request**:
```bash
curl -X GET \
  "https://api.cloudsploit.com/api/v1/scanqueue?page_size=10&statuses=pending&statuses=in_progress" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/json"
```

### 2. List Scanners

Lists all currently running scanners.

**Endpoint**: `GET /api/v1/scanqueue/scanners`

**Authentication**: Bearer token or basic auth

**Query Parameters**:
- `page_size` (integer, optional): Default 5
- `page` (integer, optional): Default 1

**Response**:
```json
{
  "count": 2,
  "page": 1,
  "pagesize": 5,
  "result": [
    {
      "id": "scanner-pod-123:15283",
      "last_heartbeat": "2024-01-09T11:54:23.474367Z",
      "status": "working",
      "scanning_registry": "Docker Hub",
      "scanning_image": "redis:latest"
    },
    {
      "id": "scanner-pod-456:15795",
      "last_heartbeat": "2024-01-09T11:54:19.912469Z",
      "status": "waiting",
      "scanning_registry": "",
      "scanning_image": ""
    }
  ]
}
```

**Scanner Status Values**:
- `working`: Currently scanning an image
- `waiting`: Idle, ready for new scan

### 3. Get Queue Summary

Returns aggregate counts of scan queue jobs.

**Endpoint**: `GET /api/v1/scanqueue/summary`

**Authentication**: Bearer token or basic auth

**Response**:
```json
{
  "total": 100,
  "pending": 25,
  "in_progress": 10,
  "finished": 60,
  "failed": 5
}
```

### 4. Cancel Jobs

Cancels pending scan jobs (jobs not yet started).

**Endpoint**: `POST /api/v1/scanqueue/cancel_jobs`

**Authentication**: Bearer token or basic auth

**Request Body**:
```json
{
  "jobs": [
    {
      "registry": "Docker Hub",
      "image": "redis:latest"
    },
    {
      "registry": "Private Registry",
      "image": "myapp:2.0"
    }
  ]
}
```

**Response**: `204 No Content` (success)

**Note**: Only pending jobs can be cancelled. In-progress jobs cannot be stopped.

### 5. Requeue Jobs

Restarts finished or failed scan jobs.

**Endpoint**: `POST /api/v1/scanqueue/requeue_jobs`

**Authentication**: Bearer token or basic auth

**Request Body**: Same format as Cancel Jobs

**Response**: `204 No Content` (success)

**Note**: Re-created jobs are added to the back of the queue.

### 6. Clear Queue

Removes all finished and failed jobs from the queue.

**Endpoint**: `POST /api/v1/scanqueue/clear`

**Authentication**: Bearer token or basic auth

**Request Body**: None

**Response**: `204 No Content` (success)

**Note**: Does not affect pending or in-progress jobs.

---

## Images API (v2)

More advanced APIs for image management.

### 1. Get Image Information

Retrieves comprehensive information about a specific image.

**Endpoint**: `GET /images/{registry}/{repository}/{tag}`

**Authentication**: Bearer token

**Path Parameters**:
- `registry` (string, required): Registry name (max 255 chars)
- `repository` (string, required): Repository name (max 255 chars)
- `tag` (string, required): Tag name (max 255 chars)

**Response**: Detailed image metadata including:
- Scan status
- Vulnerabilities by severity
- Image layers
- OS information
- Compliance status

### 2. List Registered Images

Lists all images registered in Aqua.

**Endpoint**: `GET /v2/images`

**Authentication**: Bearer token

**Query Parameters**: Supports filtering and pagination

### 3. Register Image

Registers an image for scanning.

**Endpoint**: `POST /v2/images`

**Authentication**: Bearer token

**Request Body**:
```json
{
  "registry": "Docker Hub",
  "repository": "library/nginx",
  "tag": "latest"
}
```

### 4. List Image Vulnerabilities

Retrieves vulnerability list for a specific image.

**Endpoint**: `GET /v2/images/{registry}/{repository}/{tag}/vulnerabilities`

**Authentication**: Bearer token

**Response**: Detailed CVE information with:
- CVE ID
- CVSS score
- Severity
- Fix availability
- Package information

### 5. Get Image Scan History

Retrieves historical scan records for an image.

**Endpoint**: `GET /v2/images/{registry}/{repository}/{tag}/scan_history`

**Authentication**: Bearer token

**Response**: Array of scan events with timestamps and results

---

## Implementation Guide

### Workflow for Aqua Scan Gate Controller

Here's the recommended implementation flow for the controller:

#### 1. Initialize Aqua Client

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "time"
)

type AquaClient struct {
    BaseURL   string
    APIKey    string
    APISecret string
    Region    string
    client    *http.Client
    token     string
    tokenExp  time.Time
}

func (c *AquaClient) getBaseURL() string {
    regions := map[string]string{
        "us":        "https://api.cloudsploit.com",
        "eu":        "https://eu-1.api.cloudsploit.com",
        "singapore": "https://asia-1.api.cloudsploit.com",
        "sydney":    "https://ap-2.api.cloudsploit.com",
    }
    return regions[c.Region]
}
```

#### 2. Authenticate and Get Token

```go
func (c *AquaClient) Authenticate(ctx context.Context) error {
    timestamp := fmt.Sprintf("%d", time.Now().Unix())
    method := "POST"
    path := "/v2/tokens"
    body := `{"validity":240,"allowed_endpoints":["GET","POST","PUT","DELETE"]}`

    // Create HMAC signature
    stringToSign := timestamp + method + path + body
    h := hmac.New(sha256.New, []byte(c.APISecret))
    h.Write([]byte(stringToSign))
    signature := hex.EncodeToString(h.Sum(nil))

    // Make request
    url := c.getBaseURL() + path
    req, _ := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
    req.Header.Set("X-API-Key", c.APIKey)
    req.Header.Set("X-Timestamp", timestamp)
    req.Header.Set("X-Signature", signature)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var result struct {
        Status int    `json:"status"`
        Data   string `json:"data"`
    }
    json.NewDecoder(resp.Body).Decode(&result)

    c.token = result.Data
    c.tokenExp = time.Now().Add(240 * time.Minute)

    return nil
}
```

#### 3. Check if Image Already Scanned

```go
func (c *AquaClient) GetScanStatus(ctx context.Context, registry, image string) (string, error) {
    // Ensure we have a valid token
    if time.Now().After(c.tokenExp) {
        if err := c.Authenticate(ctx); err != nil {
            return "", err
        }
    }

    // URL encode registry name
    registryEncoded := url.PathEscape(registry)
    imageEncoded := url.PathEscape(image)

    url := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/status",
        c.getBaseURL(), registryEncoded, imageEncoded)

    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    req.Header.Set("Authorization", "Bearer "+c.token)
    req.Header.Set("Accept", "application/json")

    resp, err := c.client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode == 404 {
        return "Not Found", nil
    }

    var result struct {
        Status string `json:"status"`
    }
    json.NewDecoder(resp.Body).Decode(&result)

    return result.Status, nil
}
```

#### 4. Trigger Scan if Needed

```go
func (c *AquaClient) TriggerScan(ctx context.Context, registry, image, webhookURL string) error {
    registryEncoded := url.PathEscape(registry)
    imageEncoded := url.PathEscape(image)

    url := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/scan",
        c.getBaseURL(), registryEncoded, imageEncoded)

    body := ""
    if webhookURL != "" {
        body = fmt.Sprintf(`{"webhook_url":"%s"}`, webhookURL)
    }

    req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+c.token)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return fmt.Errorf("scan trigger failed: %d", resp.StatusCode)
    }

    return nil
}
```

#### 5. Poll for Scan Completion

```go
func (c *AquaClient) WaitForScan(ctx context.Context, registry, image string, timeout time.Duration) error {
    ctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return fmt.Errorf("scan timeout")
        case <-ticker.C:
            status, err := c.GetScanStatus(ctx, registry, image)
            if err != nil {
                return err
            }

            switch status {
            case "Scanned":
                return nil
            case "Fail":
                return fmt.Errorf("scan failed")
            case "Pending", "In Progress":
                // Continue waiting
                continue
            }
        }
    }
}
```

#### 6. Retrieve and Evaluate Results

```go
type ScanResult struct {
    ImageName   string `json:"image_name"`
    Registry    string `json:"registry"`
    Disallowed  bool   `json:"disallowed"`
    CVEsCounts  struct {
        Total       int     `json:"total"`
        Critical    int     `json:"critical"`
        High        int     `json:"high"`
        Medium      int     `json:"medium"`
        Low         int     `json:"low"`
        ScoreAvg    float64 `json:"score_average"`
    } `json:"cves_counts"`
}

func (c *AquaClient) GetScanResults(ctx context.Context, registry, image string) (*ScanResult, error) {
    registryEncoded := url.PathEscape(registry)
    imageEncoded := url.PathEscape(image)

    url := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/scan_result",
        c.getBaseURL(), registryEncoded, imageEncoded)

    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    req.Header.Set("Authorization", "Bearer "+c.token)
    req.Header.Set("Accept", "application/json")

    resp, err := c.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result ScanResult
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return &result, nil
}
```

#### 7. Policy Evaluation Example

```go
func evaluatePolicy(result *ScanResult) (bool, string) {
    // Fail if disallowed by Aqua policy
    if result.Disallowed {
        return false, "Image blocked by Aqua policy"
    }

    // Fail if critical vulnerabilities found
    if result.CVEsCounts.Critical > 0 {
        return false, fmt.Sprintf("Critical vulnerabilities found: %d", result.CVEsCounts.Critical)
    }

    // Fail if high vulnerabilities exceed threshold
    if result.CVEsCounts.High > 10 {
        return false, fmt.Sprintf("Too many high vulnerabilities: %d", result.CVEsCounts.High)
    }

    // Pass
    return true, "Scan passed policy requirements"
}
```

### Error Handling Best Practices

1. **Token Expiration**: Always check token expiration and re-authenticate
2. **Rate Limiting**: Implement backoff for 429 responses
3. **Timeouts**: Set reasonable timeouts for scans (large images can take 5-10 minutes)
4. **Retries**: Implement exponential backoff for transient failures
5. **Image Parsing**: Handle various image formats:
   - `nginx:latest`
   - `gcr.io/project/image:tag`
   - `registry.io:5000/repo/image:tag`
   - `image@sha256:digest`

### Image Reference Parsing

```go
import "strings"

type ImageRef struct {
    Registry   string
    Repository string
    Tag        string
    Digest     string
}

func ParseImageRef(image string) (*ImageRef, error) {
    ref := &ImageRef{}

    // Handle digest
    if strings.Contains(image, "@") {
        parts := strings.Split(image, "@")
        image = parts[0]
        ref.Digest = parts[1]
    }

    // Handle tag
    tagIdx := strings.LastIndex(image, ":")
    if tagIdx > 0 {
        ref.Tag = image[tagIdx+1:]
        image = image[:tagIdx]
    } else {
        ref.Tag = "latest"
    }

    // Handle registry and repository
    slashIdx := strings.Index(image, "/")
    if slashIdx > 0 && (strings.Contains(image[:slashIdx], ".") || strings.Contains(image[:slashIdx], ":")) {
        ref.Registry = image[:slashIdx]
        ref.Repository = image[slashIdx+1:]
    } else {
        ref.Registry = "Docker Hub"
        ref.Repository = image
    }

    return ref, nil
}
```

---

## Common Response Formats

### Success Response

```json
{
  "status": 200,
  "code": 0,
  "data": { }
}
```

### Error Response

```json
{
  "status": 400,
  "code": 1001,
  "message": "Error description",
  "errors": [
    {
      "field": "image",
      "message": "Invalid image format"
    }
  ]
}
```

### Common HTTP Status Codes

- `200 OK`: Success
- `204 No Content`: Success with no response body
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Invalid or expired token
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found (e.g., image not scanned)
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side error

---

## Notes and Limitations

### API Rate Limits

While not explicitly documented, consider implementing:
- Request throttling (max 10 requests/second recommended)
- Exponential backoff for retries
- Connection pooling for efficiency

### Registry Requirements

- Registries must be pre-configured in Aqua console
- Private registries require credentials to be set up in Aqua
- Registry names must match exactly (case-sensitive)

### Scan Duration

Typical scan times:
- Small images (< 100MB): 30-60 seconds
- Medium images (100-500MB): 1-3 minutes
- Large images (> 500MB): 3-10 minutes

Plan polling intervals accordingly.

### Webhook Considerations

If using webhooks for async results:
- Webhook URL must be publicly accessible
- HTTPS recommended
- Implement signature verification for security
- Handle duplicate callbacks (scans can be retried)

### API Version Compatibility

This documentation is based on Aqua SaaS Platform API (2024):
- v1 APIs: Stable, widely supported
- v2 APIs: Enhanced features, recommended for new implementations
- Self-hosted Aqua may have different endpoints

Always verify against your specific Aqua deployment version.

---

## Additional Resources

- [Aqua Security Official Documentation](https://docs.aquasec.com/)
- [Aqua API Reference](https://docs.aquasec.com/saas/api-reference/)
- [Aqua Support Portal](https://support.aquasec.com/)

---

**Document Version**: 1.0
**Last Updated**: 2024-01-09
**Author**: Claude Code (AI Assistant)
