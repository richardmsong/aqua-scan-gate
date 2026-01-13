// Package imageref provides shared utilities for extracting and processing
// container image references from Kubernetes pod specifications.
package imageref

import (
	"crypto/sha256"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// ImageRef represents a container image reference with its digest.
type ImageRef struct {
	// Image is the full image reference (e.g., nginx:latest or registry.example.com/app@sha256:abc...)
	Image string
	// Digest is the sha256 digest if present in the image reference
	Digest string
}

// ExtractFromPodSpec extracts all unique image references from a PodSpec.
// It includes images from init containers, regular containers, and ephemeral containers.
func ExtractFromPodSpec(spec *corev1.PodSpec) []ImageRef {
	var images []ImageRef
	seen := make(map[string]bool)

	addImage := func(image string) {
		if image == "" || seen[image] {
			return
		}
		seen[image] = true

		// Extract digest if present in image reference
		digest := ""
		if idx := strings.Index(image, "@sha256:"); idx != -1 {
			digest = image[idx+1:]
		}

		images = append(images, ImageRef{
			Image:  image,
			Digest: digest,
		})
	}

	for _, c := range spec.InitContainers {
		addImage(c.Image)
	}
	for _, c := range spec.Containers {
		addImage(c.Image)
	}
	for _, c := range spec.EphemeralContainers {
		addImage(c.Image)
	}

	return images
}

// ExtractFromPod extracts all unique image references from a Pod.
func ExtractFromPod(pod *corev1.Pod) []ImageRef {
	return ExtractFromPodSpec(&pod.Spec)
}

// ScanName generates a deterministic name for an ImageScan CR based on the image reference.
// If the image has a digest, it uses a sanitized version of the digest.
// Otherwise, it hashes the image reference.
func ScanName(img ImageRef) string {
	// Use digest if available, otherwise hash the image reference
	if img.Digest != "" {
		// sha256:abc123... -> sha256-abc123...
		name := strings.ReplaceAll(img.Digest, ":", "-")
		if len(name) > 63 {
			return name[:63]
		}
		return name
	}
	return fmt.Sprintf("img-%s", HashString(img.Image)[:56])
}

// HashString returns the SHA256 hash of a string as a hex-encoded string.
func HashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}
