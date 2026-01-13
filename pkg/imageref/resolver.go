// Package imageref provides shared utilities for extracting and processing
// container image references from Kubernetes pod specifications.
package imageref

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Resolver resolves image tags to digests by querying the registry.
type Resolver struct {
	// Platform specifies the target platform for multi-arch images.
	// Defaults to linux/amd64.
	Platform v1.Platform
	// Options are additional options for remote operations (auth, transport, etc.)
	Options []remote.Option
}

// NewResolver creates a new Resolver with default settings (linux/amd64).
func NewResolver(opts ...remote.Option) *Resolver {
	return &Resolver{
		Platform: v1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		Options: opts,
	}
}

// ResolveDigest resolves an image reference to its digest.
// If the image already has a digest, it returns that digest.
// For tag-based references, it queries the registry to get the digest.
// For multi-arch images (index), it resolves to the linux/amd64 manifest digest.
func (r *Resolver) ResolveDigest(ctx context.Context, imageRef string) (string, error) {
	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parsing image reference: %w", err)
	}

	// If it's already a digest reference, extract and return the digest
	if digestRef, ok := ref.(name.Digest); ok {
		return digestRef.DigestStr(), nil
	}

	// Add context to options
	opts := append([]remote.Option{remote.WithContext(ctx)}, r.Options...)

	// Try to get as an index (multi-arch image) first
	idx, err := remote.Index(ref, opts...)
	if err == nil {
		// It's a multi-arch image, find the linux/amd64 manifest
		digest, err := r.resolveFromIndex(idx)
		if err != nil {
			return "", fmt.Errorf("resolving from index: %w", err)
		}
		return digest, nil
	}

	// Not an index, try as a single image
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return "", fmt.Errorf("fetching image: %w", err)
	}

	digest, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("getting digest: %w", err)
	}

	return digest.String(), nil
}

// resolveFromIndex finds the digest for the target platform from an image index.
func (r *Resolver) resolveFromIndex(idx v1.ImageIndex) (string, error) {
	indexManifest, err := idx.IndexManifest()
	if err != nil {
		return "", fmt.Errorf("getting index manifest: %w", err)
	}

	for _, manifest := range indexManifest.Manifests {
		if manifest.Platform == nil {
			continue
		}
		if manifest.Platform.OS == r.Platform.OS &&
			manifest.Platform.Architecture == r.Platform.Architecture {
			return manifest.Digest.String(), nil
		}
	}

	return "", fmt.Errorf("no manifest found for platform %s/%s", r.Platform.OS, r.Platform.Architecture)
}

// ResolveImageRef resolves an ImageRef, populating the Digest field if empty.
// Returns a new ImageRef with the resolved digest.
func (r *Resolver) ResolveImageRef(ctx context.Context, img ImageRef) (ImageRef, error) {
	// If already has a digest, return as-is
	if img.Digest != "" {
		return img, nil
	}

	digest, err := r.ResolveDigest(ctx, img.Image)
	if err != nil {
		return img, err
	}

	return ImageRef{
		Image:  img.Image,
		Digest: digest,
	}, nil
}
