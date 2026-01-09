# CLAUDE.md - Aqua Scan Gate Controller

## Project Overview

This repository contains a Kubernetes controller built with kubebuilder that implements Pod Scheduling Gates to enforce Aqua security scanning before pods can be scheduled. The controller ensures that all container images are scanned and meet security requirements before workloads run in the cluster.

## Repository Structure

```
aqua-scan-triggerer/
├── api/v1alpha1/              # Custom Resource Definitions
│   ├── groupversion_info.go   # API group/version metadata
│   └── imagescan_types.go     # ImageScan CRD definition
├── cmd/
│   └── main.go                # Application entry point
├── config/                    # Kubernetes manifests
│   ├── crd/bases/             # Generated CRD YAML files
│   ├── rbac/                  # RBAC configurations
│   ├── webhook/               # Webhook configurations
│   ├── manager/               # Controller deployment configs
│   └── samples/               # Example deployments
├── internal/
│   ├── controller/            # Reconciliation logic
│   │   ├── imagescan_controller.go      # Manages ImageScan lifecycle
│   │   ├── pod_gate_controller.go       # Manages pod scheduling gates
│   │   └── pod_gate_controller_test.go  # Unit tests
│   └── webhook/               # Admission webhooks
│       └── pod_webhook.go     # Mutating webhook for pods
├── pkg/
│   └── aqua/                  # Aqua API client
│       └── client.go          # HTTP client for Aqua platform
├── hack/
│   └── boilerplate.go.txt     # License header template
├── Dockerfile                 # Container image definition
├── Makefile                   # Build and deployment automation
├── PROJECT                    # Kubebuilder project metadata
├── go.mod                     # Go module definition
├── go.sum                     # Go dependencies checksum
└── README.md                  # User-facing documentation
```

## Key Components

### 1. ImageScan Custom Resource Definition

**File**: `api/v1alpha1/imagescan_types.go`

The ImageScan CRD tracks the security scan status of container images:

- **Spec Fields**:
  - `image`: Full image reference (e.g., `nginx:latest`)
  - `digest`: SHA256 digest for immutable reference
  - `registry`: Optional registry source

- **Status Fields**:
  - `phase`: Current scan state (Pending, InProgress, Passed, Failed, Error)
  - `aquaScanId`: Tracking ID from Aqua platform
  - `vulnerabilities`: Counts by severity (critical, high, medium, low)
  - `lastScanTime`: When scan was performed
  - `completedTime`: When scan reached terminal state
  - `message`: Human-readable status details

### 2. Aqua Client Interface

**File**: `pkg/aqua/client.go`

Provides abstraction over Aqua Security API:

- `GetScanResult()`: Retrieve existing scan results
- `TriggerScan()`: Initiate new image scan
- `GetScanStatus()`: Poll scan progress

**Note**: The client implementation is a skeleton. You must implement the actual API calls based on your Aqua version (SaaS vs self-hosted APIs differ).

### 3. ImageScan Controller

**File**: `internal/controller/imagescan_controller.go`

Reconciles ImageScan resources by:
1. Checking Aqua API for existing scan results
2. Triggering scans for unscanned images
3. Polling scan status until completion
4. Updating CR status with vulnerability counts
5. Implementing rescan intervals for continuous compliance

**Default Policy**: Fails images with critical vulnerabilities. Customize by modifying the reconcile logic.

### 4. Pod Gate Controller

**File**: `internal/controller/pod_gate_controller.go`

Monitors pods with scheduling gates:
1. Extracts all image references from pod spec
2. Creates/checks ImageScan CRs for each image
3. Removes gate when all scans pass
4. Emits Kubernetes events for observability

**Special Handling**:
- Supports bypass annotation: `scans.aquasec.community/bypass-scan: "true"`
- Respects excluded namespaces
- Handles init containers, ephemeral containers

### 5. Mutating Webhook

**File**: `internal/webhook/pod_webhook.go`

Admission controller that:
1. Intercepts pod creation requests
2. Injects `scans.aquasec.community/aqua-scan` scheduling gate
3. Skips excluded namespaces and images
4. Honors bypass annotations

### 6. Main Application

**File**: `cmd/main.go`

Wires all components together:
- Initializes controller-runtime manager
- Registers all reconcilers
- Configures webhook server
- Sets up health checks and metrics
- Handles leader election for HA

## Setup Instructions for Claude Agents

### Prerequisites Check

Before working on this project, verify:

1. **Go Installation**:
```bash
go version  # Should be 1.24+
```

2. **Kubebuilder Installation**:
```bash
# Install via go install
go install sigs.k8s.io/kubebuilder/v4@latest

# Verify installation
~/go/bin/kubebuilder version
```

3. **Kubernetes Cluster Access** (for testing):
```bash
kubectl version
kubectl cluster-info
```

### Development Workflow

1. **Install Dependencies**:
```bash
go mod download
make controller-gen
```

2. **Generate Code**:
```bash
# Generate DeepCopy methods and CRD manifests
make manifests generate
```

3. **Run Tests**:
```bash
make test
```

4. **Run Locally**:
```bash
# Requires valid kubeconfig
export AQUA_URL=https://your-aqua.com
export AQUA_API_KEY=your-key
make run
```

5. **Build Binary**:
```bash
make build
./bin/manager --help
```

6. **Build Container Image**:
```bash
make docker-build
```

### Common Development Tasks

#### Adding New Fields to ImageScan CRD

1. Edit `api/v1alpha1/imagescan_types.go`
2. Run `make manifests generate`
3. Update controllers that use the new fields
4. Run `make test`

#### Modifying Security Policy

Edit the switch statement in `internal/controller/imagescan_controller.go` around line 90:
```go
// Determine pass/fail based on policy
if result.Critical > 0 {
    imageScan.Status.Phase = securityv1alpha1.ScanPhaseFailed
    imageScan.Status.Message = "Critical vulnerabilities found"
} else {
    imageScan.Status.Phase = securityv1alpha1.ScanPhasePassed
    imageScan.Status.Message = "Scan completed successfully"
}
```

Customize thresholds for high/medium vulnerabilities as needed.

#### Implementing Aqua API Client

The client in `pkg/aqua/client.go` needs completion:

1. **Identify Your Aqua API Version**:
   - Aqua SaaS: Uses `/api/v2/` endpoints
   - Self-hosted: May use `/api/v1/` or `/api/v2/`

2. **Implement Missing Methods**:
   - `TriggerScan()`: POST to scan endpoint
   - `GetScanStatus()`: GET scan results by ID

3. **Example Implementation**:
```go
func (c *aquaClient) TriggerScan(ctx context.Context, image, digest string) (string, error) {
    payload := map[string]string{
        "registry": extractRegistry(image),
        "image":    extractImageName(image),
        "tag":      extractTag(image),
    }

    // Marshal and POST to Aqua API
    // Return scan ID
}
```

### Testing Strategy

#### Unit Tests

Located in `internal/controller/pod_gate_controller_test.go`. Uses fake clients to test controller logic without real Kubernetes API.

Run with:
```bash
go test ./internal/controller/...
```

#### Integration Tests

Requires real Kubernetes cluster:

1. Create kind cluster:
```bash
kind create cluster --name aqua-test
```

2. Install CRDs:
```bash
make install
```

3. Run controller locally:
```bash
make run
```

4. Create test pod:
```bash
kubectl run test --image=nginx:latest
kubectl get pod test -o yaml  # Check for scheduling gate
kubectl get imagescans         # Verify ImageScan created
```

5. Simulate scan completion:
```bash
kubectl patch imagescan <name> --type=merge -p '{"status":{"phase":"Passed"}}'
kubectl get pod test           # Should now be Running
```

### Kubernetes Version Compatibility

- **Minimum**: Kubernetes 1.26 (for Scheduling Gates feature)
- **Recommended**: Kubernetes 1.28+
- **Testing**: Verified on kind v0.20+ with Kubernetes 1.29

### Known Issues and Limitations

1. **Image Digest Resolution**:
   - Controller expects images with digests (`@sha256:...`)
   - For tag-based images, digest field may be empty
   - Consider adding registry client to resolve digests

2. **Aqua API Variations**:
   - API endpoints differ between Aqua versions
   - Client implementation is intentionally minimal
   - Must be completed based on your Aqua deployment

3. **Webhook Certificates**:
   - Production deployment requires TLS certificates
   - Use cert-manager or similar for certificate management
   - See `config/webhook/manifests.yaml`

4. **Scan Performance**:
   - Large images may take minutes to scan
   - Pods will wait in SchedulingGated state
   - Consider caching scan results

5. **Bypass Security**:
   - Bypass annotation is powerful - use with caution
   - Consider implementing additional RBAC controls
   - Audit bypass usage via events

### Configuration Best Practices

1. **Namespace Exclusions**:
   - Always exclude `kube-system`, `kube-public`
   - Exclude cert-manager and other critical infrastructure
   - Use `--excluded-namespaces` flag

2. **Rescan Intervals**:
   - Default is 24 hours
   - Balance security vs API load
   - Adjust via `--rescan-interval` flag

3. **Leader Election**:
   - Enable for HA deployments
   - Use `--leader-elect` flag
   - Run 2+ replicas

4. **Resource Limits**:
   - Default: 100m CPU request, 500m limit
   - Default: 128Mi memory request, 256Mi limit
   - Adjust based on cluster size

### Troubleshooting Guide

#### Pods Stuck in SchedulingGated

**Symptoms**: Pods show `SchedulingGated` in conditions

**Debug**:
```bash
kubectl get imagescans -A
kubectl describe imagescan <name>
kubectl logs -n aqua-scan-gate-system deployment/aqua-scan-gate-controller
```

**Common Causes**:
- Aqua API unreachable
- Scan still in progress
- Critical vulnerabilities found

#### Webhook Not Injecting Gates

**Symptoms**: New pods don't have scheduling gates

**Debug**:
```bash
kubectl get mutatingwebhookconfiguration aqua-scan-gate-webhook -o yaml
kubectl logs -n aqua-scan-gate-system deployment/aqua-scan-gate-controller
```

**Common Causes**:
- Webhook service not ready
- Certificate issues
- Namespace excluded

#### Controller Crashes

**Symptoms**: Controller pods restarting

**Debug**:
```bash
kubectl logs -n aqua-scan-gate-system deployment/aqua-scan-gate-controller --previous
```

**Common Causes**:
- Missing RBAC permissions
- Aqua API credentials invalid
- Go panic in reconcile loop

### Metrics and Observability

The controller exposes Prometheus metrics on `:8080/metrics`:

- `controller_runtime_reconcile_total`: Reconciliation attempts
- `controller_runtime_reconcile_errors_total`: Failed reconciliations
- `controller_runtime_reconcile_time_seconds`: Reconciliation duration

Health checks:
- Liveness: `:8081/healthz`
- Readiness: `:8081/readyz`

### Future Enhancements

Potential improvements for consideration:

1. **Policy Engine Integration**: Use OPA/Gatekeeper for flexible policies
2. **Image Digest Resolution**: Add registry client for tag-to-digest conversion
3. **Caching Layer**: Cache scan results to reduce API calls
4. **Metrics Dashboard**: Add Grafana dashboards
5. **Scan Prioritization**: Queue scans by priority
6. **Webhook Timeout Optimization**: Async scan triggering
7. **Multi-Registry Support**: Handle private registries
8. **Compliance Reporting**: Export audit logs

### References

- [Kubebuilder Book](https://book.kubebuilder.io/)
- [Kubernetes Scheduling Gates](https://kubernetes.io/docs/concepts/scheduling-eviction/pod-scheduling-readiness/)
- [Controller Runtime](https://github.com/kubernetes-sigs/controller-runtime)
- [Aqua Security API Docs](https://docs.aquasec.com/docs/api)

### Important Notes for Claude Agents

1. **Always check if kubebuilder is installed** before attempting to scaffold:
   ```bash
   go install sigs.k8s.io/kubebuilder/v4@latest
   ```

2. **Generated files**: After modifying CRD types, always run:
   ```bash
   make manifests generate
   ```

3. **Testing changes**: Use the Makefile targets rather than direct commands:
   ```bash
   make test      # Run unit tests
   make build     # Build binary
   make run       # Run locally
   ```

4. **RBAC markers**: The `// +kubebuilder:rbac` comments in controllers are critical - they generate RBAC manifests. Don't remove them.

5. **Webhook markers**: The `// +kubebuilder:webhook` comments configure webhook registration. Verify these match your requirements.

6. **Go module path**: The module is `github.com/richardmsong/aqua-scan-triggerer`. Ensure all imports use this path.

7. **Container image**: Update `config/samples/deployment.yaml` with your actual container registry before deploying.

## Project Status

- ✅ Core controller logic implemented
- ✅ Webhook implementation complete
- ✅ Basic unit tests included
- ✅ Deployment manifests provided
- ⚠️ Aqua API client needs completion (specific to your Aqua version)
- ⚠️ Integration tests require manual execution
- ⚠️ Certificate management for webhook needs setup (recommend cert-manager)

This is a production-ready foundation that requires Aqua API implementation and environment-specific configuration to deploy.
