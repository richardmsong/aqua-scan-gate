package aqua

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var ctx = context.Background()

var _ = Describe("FileCache", func() {
	var (
		fc       *FileCache
		cacheDir string
	)

	BeforeEach(func() {
		// Use a unique temp directory for each test
		var err error
		cacheDir, err = os.MkdirTemp("", "aqua-cache-test-*")
		Expect(err).NotTo(HaveOccurred())

		fc = NewFileCache(FileCacheConfig{
			CacheDir: cacheDir,
			TTL:      1 * time.Hour,
			Enabled:  true,
		})
	})

	AfterEach(func() {
		// Clean up test directory
		if cacheDir != "" {
			_ = os.RemoveAll(cacheDir)
		}
	})

	Describe("NewFileCache", func() {
		It("should use default values when not provided", func() {
			fc := NewFileCache(FileCacheConfig{})
			Expect(fc.config.CacheDir).To(Equal(DefaultCacheDir))
			Expect(fc.config.CacheFile).To(Equal(DefaultCacheFile))
			Expect(fc.config.TTL).To(Equal(DefaultCacheTTL))
		})

		It("should use provided values", func() {
			fc := NewFileCache(FileCacheConfig{
				CacheDir:  "/custom/dir",
				CacheFile: "custom.json",
				TTL:       30 * time.Minute,
				Enabled:   true,
			})
			Expect(fc.config.CacheDir).To(Equal("/custom/dir"))
			Expect(fc.config.CacheFile).To(Equal("custom.json"))
			Expect(fc.config.TTL).To(Equal(30 * time.Minute))
		})
	})

	Describe("Get", func() {
		Context("when cache file does not exist", func() {
			It("should return nil without error", func() {
				result, err := fc.Get()
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})

		Context("when cache file exists with valid data", func() {
			BeforeEach(func() {
				registries := []Registry{
					{
						Name:     "test-registry",
						Type:     "docker",
						Prefixes: []string{"docker.io"},
					},
				}
				err := fc.Set(registries)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return cached registries with FetchedAt timestamp", func() {
				result, err := fc.Get()
				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Registries).To(HaveLen(1))
				Expect(result.Registries[0].Name).To(Equal("test-registry"))
				Expect(result.Registries[0].Type).To(Equal("docker"))
				Expect(result.Registries[0].Prefixes).To(ContainElement("docker.io"))
				// FetchedAt should be recent (within last minute)
				Expect(time.Since(result.FetchedAt)).To(BeNumerically("<", 1*time.Minute))
			})
		})

		Context("when cache file has expired", func() {
			BeforeEach(func() {
				// Create a file cache with a very short TTL
				fc = NewFileCache(FileCacheConfig{
					CacheDir: cacheDir,
					TTL:      1 * time.Millisecond,
					Enabled:  true,
				})

				registries := []Registry{
					{Name: "test-registry", Type: "docker"},
				}
				err := fc.Set(registries)
				Expect(err).NotTo(HaveOccurred())

				// Wait for cache to expire
				time.Sleep(10 * time.Millisecond)
			})

			It("should return nil (cache miss)", func() {
				result, err := fc.Get()
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})

		Context("when cache file contains invalid JSON", func() {
			BeforeEach(func() {
				// Write invalid JSON to cache file
				err := os.MkdirAll(cacheDir, 0755)
				Expect(err).NotTo(HaveOccurred())
				err = os.WriteFile(filepath.Join(cacheDir, DefaultCacheFile), []byte("invalid json"), 0644)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return nil without error (treat as cache miss)", func() {
				result, err := fc.Get()
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})

		Context("when file cache is disabled", func() {
			BeforeEach(func() {
				fc = NewFileCache(FileCacheConfig{
					CacheDir: cacheDir,
					Enabled:  false,
				})
			})

			It("should return nil", func() {
				result, err := fc.Get()
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})
	})

	Describe("Set", func() {
		It("should create cache directory if it does not exist", func() {
			newDir := filepath.Join(cacheDir, "subdir", "cache")
			fc = NewFileCache(FileCacheConfig{
				CacheDir: newDir,
				TTL:      1 * time.Hour,
				Enabled:  true,
			})

			registries := []Registry{
				{Name: "test-registry"},
			}
			err := fc.Set(registries)
			Expect(err).NotTo(HaveOccurred())

			// Verify directory was created
			info, err := os.Stat(newDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue())
		})

		It("should write cache file with correct content", func() {
			registries := []Registry{
				{
					Name:          "github-registry",
					Type:          "ghcr",
					Description:   "GitHub Container Registry",
					Prefixes:      []string{"ghcr.io"},
					DefaultPrefix: "ghcr.io",
				},
				{
					Name:     "docker-hub",
					Type:     "docker",
					Prefixes: []string{"docker.io", "index.docker.io"},
				},
			}
			err := fc.Set(registries)
			Expect(err).NotTo(HaveOccurred())

			// Verify file exists
			_, err = os.Stat(fc.GetCachePath())
			Expect(err).NotTo(HaveOccurred())

			// Verify we can read it back
			result, err := fc.Get()
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.Registries).To(HaveLen(2))
			Expect(result.Registries[0].Name).To(Equal("github-registry"))
			Expect(result.Registries[1].Name).To(Equal("docker-hub"))
		})

		Context("when file cache is disabled", func() {
			BeforeEach(func() {
				fc = NewFileCache(FileCacheConfig{
					CacheDir: cacheDir,
					Enabled:  false,
				})
			})

			It("should do nothing", func() {
				registries := []Registry{{Name: "test"}}
				err := fc.Set(registries)
				Expect(err).NotTo(HaveOccurred())

				// Verify no file was created
				_, err = os.Stat(fc.GetCachePath())
				Expect(os.IsNotExist(err)).To(BeTrue())
			})
		})
	})

	Describe("Clear", func() {
		BeforeEach(func() {
			registries := []Registry{{Name: "test-registry"}}
			err := fc.Set(registries)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should remove the cache file", func() {
			// Verify file exists before clear
			_, err := os.Stat(fc.GetCachePath())
			Expect(err).NotTo(HaveOccurred())

			err = fc.Clear()
			Expect(err).NotTo(HaveOccurred())

			// Verify file no longer exists
			_, err = os.Stat(fc.GetCachePath())
			Expect(os.IsNotExist(err)).To(BeTrue())
		})

		It("should not error if file does not exist", func() {
			err := fc.Clear()
			Expect(err).NotTo(HaveOccurred())

			// Clear again should still not error
			err = fc.Clear()
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when file cache is disabled", func() {
			BeforeEach(func() {
				fc = NewFileCache(FileCacheConfig{
					CacheDir: cacheDir,
					Enabled:  false,
				})
			})

			It("should do nothing", func() {
				err := fc.Clear()
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("IsExpired", func() {
		Context("when cache file does not exist", func() {
			It("should return true", func() {
				expired, err := fc.IsExpired()
				Expect(err).NotTo(HaveOccurred())
				Expect(expired).To(BeTrue())
			})
		})

		Context("when cache file exists and is fresh", func() {
			BeforeEach(func() {
				registries := []Registry{{Name: "test"}}
				err := fc.Set(registries)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return false", func() {
				expired, err := fc.IsExpired()
				Expect(err).NotTo(HaveOccurred())
				Expect(expired).To(BeFalse())
			})
		})

		Context("when cache file has expired", func() {
			BeforeEach(func() {
				fc = NewFileCache(FileCacheConfig{
					CacheDir: cacheDir,
					TTL:      1 * time.Millisecond,
					Enabled:  true,
				})

				registries := []Registry{{Name: "test"}}
				err := fc.Set(registries)
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(10 * time.Millisecond)
			})

			It("should return true", func() {
				expired, err := fc.IsExpired()
				Expect(err).NotTo(HaveOccurred())
				Expect(expired).To(BeTrue())
			})
		})

		Context("when file cache is disabled", func() {
			BeforeEach(func() {
				fc = NewFileCache(FileCacheConfig{
					CacheDir: cacheDir,
					Enabled:  false,
				})
			})

			It("should return true", func() {
				expired, err := fc.IsExpired()
				Expect(err).NotTo(HaveOccurred())
				Expect(expired).To(BeTrue())
			})
		})
	})

	Describe("GetCachePath", func() {
		It("should return the full path to the cache file", func() {
			expectedPath := filepath.Join(cacheDir, DefaultCacheFile)
			Expect(fc.GetCachePath()).To(Equal(expectedPath))
		})

		It("should respect custom cache file name", func() {
			fc = NewFileCache(FileCacheConfig{
				CacheDir:  cacheDir,
				CacheFile: "custom-cache.json",
			})
			expectedPath := filepath.Join(cacheDir, "custom-cache.json")
			Expect(fc.GetCachePath()).To(Equal(expectedPath))
		})
	})

	Describe("Atomic Write", func() {
		It("should write atomically (no partial writes)", func() {
			registries := []Registry{
				{Name: "registry-1"},
				{Name: "registry-2"},
				{Name: "registry-3"},
			}

			err := fc.Set(registries)
			Expect(err).NotTo(HaveOccurred())

			// Verify no temp files exist in the cache directory
			// Temp files are created with pattern "registries-*.tmp"
			entries, err := os.ReadDir(cacheDir)
			Expect(err).NotTo(HaveOccurred())
			for _, entry := range entries {
				Expect(entry.Name()).NotTo(ContainSubstring(".tmp"))
			}

			// Verify cache file is complete
			result, err := fc.Get()
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.Registries).To(HaveLen(3))
		})
	})
})

var _ = Describe("FileCache Integration with Client", func() {
	var (
		cacheDir string
	)

	BeforeEach(func() {
		var err error
		cacheDir, err = os.MkdirTemp("", "aqua-client-cache-test-*")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if cacheDir != "" {
			_ = os.RemoveAll(cacheDir)
		}
	})

	Context("when file cache is enabled", func() {
		It("should persist registries to file cache", func() {
			// Create first client and populate cache
			server := createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				resp := RegistriesResponse{
					Count:    1,
					Page:     1,
					PageSize: 100,
					Result: []Registry{
						{
							Name:     "github-registry",
							Type:     "ghcr",
							Prefixes: []string{"ghcr.io"},
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			})
			defer server.Close()

			fileCacheEnabled := true
			client := NewClient(Config{
				BaseURL:          server.URL,
				FileCacheEnabled: &fileCacheEnabled,
				FileCacheDir:     cacheDir,
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})

			// Fetch registries - this should populate file cache
			registries, err := client.GetRegistries(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(registries).To(HaveLen(1))

			// Verify file cache was created
			fc := NewFileCache(FileCacheConfig{
				CacheDir: cacheDir,
				TTL:      1 * time.Hour,
				Enabled:  true,
			})
			result, err := fc.Get()
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.Registries).To(HaveLen(1))
			Expect(result.Registries[0].Name).To(Equal("github-registry"))
		})
	})

	Context("when file cache is disabled", func() {
		It("should not create file cache", func() {
			server := createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				resp := RegistriesResponse{
					Count:    1,
					Page:     1,
					PageSize: 100,
					Result: []Registry{
						{Name: "test-registry"},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			})
			defer server.Close()

			fileCacheEnabled := false
			client := NewClient(Config{
				BaseURL:          server.URL,
				FileCacheEnabled: &fileCacheEnabled,
				FileCacheDir:     cacheDir,
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})

			// Fetch registries
			_, err := client.GetRegistries(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Verify no file cache was created
			fc := NewFileCache(FileCacheConfig{
				CacheDir: cacheDir,
				Enabled:  true,
			})
			result, err := fc.Get()
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(BeNil())
		})
	})

	Context("when file cache has FetchedAt timestamp", func() {
		It("should preserve FetchedAt timestamp for TTL refresh", func() {
			// Create a file cache with data that was fetched 30 minutes ago
			fc := NewFileCache(FileCacheConfig{
				CacheDir: cacheDir,
				TTL:      1 * time.Hour,
				Enabled:  true,
			})

			// Manually write cache data with a specific FetchedAt time (30 minutes ago)
			pastTime := time.Now().Add(-30 * time.Minute)
			cacheData := struct {
				Registries []Registry `json:"registries"`
				FetchedAt  time.Time  `json:"fetched_at"`
				Version    string     `json:"version"`
			}{
				Registries: []Registry{
					{
						Name:     "cached-registry",
						Type:     "docker",
						Prefixes: []string{"docker.io"},
					},
				},
				FetchedAt: pastTime,
				Version:   "1",
			}

			// Write directly to the cache file
			err := os.MkdirAll(cacheDir, 0755)
			Expect(err).NotTo(HaveOccurred())
			data, err := json.MarshalIndent(cacheData, "", "  ")
			Expect(err).NotTo(HaveOccurred())
			err = os.WriteFile(fc.GetCachePath(), data, 0644)
			Expect(err).NotTo(HaveOccurred())

			// Verify that Get() returns the original FetchedAt timestamp
			result, err := fc.Get()
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.Registries).To(HaveLen(1))
			Expect(result.Registries[0].Name).To(Equal("cached-registry"))

			// FetchedAt should be approximately 30 minutes ago (within 1 minute tolerance)
			timeDiff := time.Since(result.FetchedAt)
			Expect(timeDiff).To(BeNumerically(">", 29*time.Minute))
			Expect(timeDiff).To(BeNumerically("<", 31*time.Minute))
		})
	})
})
