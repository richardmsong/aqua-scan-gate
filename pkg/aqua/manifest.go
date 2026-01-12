package aqua

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// GetConfigDigest retrieves the config digest (sha256) from a Docker image manifest.
// This is the digest that Aqua uses to identify scanned images.
func GetConfigDigest(ctx context.Context, imageRef string) (string, error) {
	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parsing image reference: %w", err)
	}

	// Fetch the image descriptor
	desc, err := remote.Get(ref, remote.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("fetching image descriptor: %w", err)
	}

	// Get the image manifest
	img, err := desc.Image()
	if err != nil {
		return "", fmt.Errorf("getting image from descriptor: %w", err)
	}

	// Extract the config file hash (this is the config digest)
	configName, err := img.ConfigName()
	if err != nil {
		return "", fmt.Errorf("getting config digest: %w", err)
	}

	// Return the digest in the format sha256:...
	return configName.String(), nil
}

// GetConfigDigestWithAuth retrieves the config digest with registry authentication.
func GetConfigDigestWithAuth(ctx context.Context, imageRef string, options ...remote.Option) (string, error) {
	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parsing image reference: %w", err)
	}

	// Add context to options
	options = append(options, remote.WithContext(ctx))

	// Fetch the image descriptor with auth options
	desc, err := remote.Get(ref, options...)
	if err != nil {
		return "", fmt.Errorf("fetching image descriptor: %w", err)
	}

	// Get the image manifest
	img, err := desc.Image()
	if err != nil {
		return "", fmt.Errorf("getting image from descriptor: %w", err)
	}

	// Extract the config file hash (this is the config digest)
	configName, err := img.ConfigName()
	if err != nil {
		return "", fmt.Errorf("getting config digest: %w", err)
	}

	// Return the digest in the format sha256:...
	return configName.String(), nil
}

// ImageInfo contains information extracted from an image manifest.
type ImageInfo struct {
	ConfigDigest   string // The config digest (sha256:...)
	ManifestDigest string // The manifest digest (sha256:...)
	Registry       string // The registry hostname
	Repository     string // The repository path
	Tag            string // The tag (or "latest" if not specified)
}

// GetImageInfo retrieves comprehensive information from an image manifest.
func GetImageInfo(ctx context.Context, imageRef string, options ...remote.Option) (*ImageInfo, error) {
	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}

	// Add context to options
	options = append(options, remote.WithContext(ctx))

	// Fetch the image descriptor
	desc, err := remote.Get(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("fetching image descriptor: %w", err)
	}

	// Get the image
	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("getting image from descriptor: %w", err)
	}

	// Extract the config digest
	configName, err := img.ConfigName()
	if err != nil {
		return nil, fmt.Errorf("getting config digest: %w", err)
	}

	// Extract the manifest digest
	manifestDigest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("getting manifest digest: %w", err)
	}

	// Extract registry, repository, and tag from reference
	registry := ref.Context().RegistryStr()
	repository := ref.Context().RepositoryStr()
	tag := "latest"

	if tagged, ok := ref.(name.Tag); ok {
		tag = tagged.TagStr()
	}

	return &ImageInfo{
		ConfigDigest:   configName.String(),
		ManifestDigest: manifestDigest.String(),
		Registry:       registry,
		Repository:     repository,
		Tag:            tag,
	}, nil
}
