# Aqua Scan Gate Controller

A Kubernetes controller that gates pod scheduling until Aqua security scans complete successfully.

## Overview

This controller uses Kubernetes Scheduling Gates (1.26+) to hold pods in a pending state until all container images pass Aqua security scanning. It provides automated security scanning enforcement at the admission control level.

## Architecture

The controller consists of three main components:

1. **Mutating Webhook**: Automatically adds a scheduling gate to new pods
2. **ImageScan Controller**: Manages the lifecycle of image security scans via Aqua API
3. **Pod Gate Controller**: Monitors ImageScan status and removes gates when scans pass

## Features

- Automatic security scanning for all pod images
- Support for init containers, regular containers, and ephemeral containers
- Configurable namespace exclusions
- Bypass mechanism via pod annotations
- Rescan intervals for continuous compliance
- Comprehensive RBAC configuration
- High availability support with leader election

## Prerequisites

- Kubernetes 1.26+ (for Scheduling Gates support)
- Aqua Security platform (SaaS or self-hosted)
- kubebuilder v4+ (for development)
- Go 1.24+

## Quick Start

### Installation

1. Install the CRDs:
```bash
make install
```

2. Create Aqua credentials secret:
```bash
kubectl create namespace aqua-scan-gate-system
kubectl create secret generic aqua-credentials \
  --namespace aqua-scan-gate-system \
  --from-literal=url=https://your-aqua-server.com \
  --from-literal=api-key=your-api-key
```

3. Deploy the controller:
```bash
make deploy
```

### Development

1. Install dependencies:
```bash
make controller-gen
```

2. Generate manifests and code:
```bash
make manifests generate
```

3. Run tests:
```bash
make test
```

4. Run locally (against your configured cluster):
```bash
make run
```

## Configuration

### Controller Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--aqua-url` | `AQUA_URL` | (required) | Aqua server URL |
| `--aqua-api-key` | `AQUA_API_KEY` | (required) | Aqua API key |
| `--excluded-namespaces` | - | `kube-system,kube-public,cert-manager` | Namespaces to skip |
| `--scan-namespace` | - | (empty = same as pod) | Where to create ImageScan CRs |
| `--rescan-interval` | - | `24h` | How often to rescan images |
| `--leader-elect` | - | `false` | Enable leader election for HA |

### Pod Annotations

- `scans.aquasec.community/bypass-scan: "true"`: Skip scanning for this pod (use with caution)

### Namespace Labels

Excluded namespaces are configured via the `--excluded-namespaces` flag. System namespaces are excluded by default.

## Custom Resources

### ImageScan

The `ImageScan` CRD tracks the security scan status for container images.

Example:
```yaml
apiVersion: scans.aquasec.community/v1alpha1
kind: ImageScan
metadata:
  name: img-abc123
  namespace: default
spec:
  image: nginx:latest
  digest: sha256:abcdef...
status:
  phase: Passed
  vulnerabilities:
    critical: 0
    high: 2
    medium: 5
    low: 10
  lastScanTime: "2026-01-08T12:00:00Z"
```

## How It Works

1. When a pod is created, the mutating webhook adds `scans.aquasec.community/aqua-scan` to its scheduling gates
2. The pod remains in `SchedulingGated` status
3. The Pod Gate Controller detects the gated pod and creates/checks ImageScan CRs for each container image
4. The ImageScan Controller queries Aqua API for scan results, triggering scans if needed
5. Once all images pass scanning (or fail), the Pod Gate Controller removes the gate
6. The pod can now be scheduled normally (if all scans passed)

## Security Policy

By default, the controller fails pods if any image has critical vulnerabilities. This policy can be customized by modifying the `ImageScanReconciler.Reconcile()` logic in `internal/controller/imagescan_controller.go`.

## Troubleshooting

### Pods stuck in SchedulingGated state

Check ImageScan resources:
```bash
kubectl get imagescans -A
kubectl describe imagescan <name>
```

### Webhook not injecting gates

Check webhook configuration:
```bash
kubectl get mutatingwebhookconfiguration aqua-scan-gate-webhook
kubectl logs -n aqua-scan-gate-system deployment/aqua-scan-gate-controller
```

### Aqua API connection issues

Verify credentials and network connectivity:
```bash
kubectl get secret -n aqua-scan-gate-system aqua-credentials
kubectl logs -n aqua-scan-gate-system deployment/aqua-scan-gate-controller
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

Apache 2.0
