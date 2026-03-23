package webhook

import (
	"context"
	"encoding/json"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var _ = Describe("PodMutator", func() {
	var (
		scheme  *runtime.Scheme
		decoder admission.Decoder
		ctx     context.Context
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		ctx = context.Background()

		var err error
		decoder = admission.NewDecoder(scheme)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("isNamespaceExcluded (Issue #59 - Whitelist Mode)", func() {
		var m *PodMutator

		BeforeEach(func() {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				Build()

			m = &PodMutator{
				Client:  fakeClient,
				Decoder: decoder,
			}
		})

		Context("when neither IncludedNamespaces nor ExcludedNamespaces are set", func() {
			It("should not exclude any namespace (default behavior)", func() {
				Expect(m.isNamespaceExcluded("default")).To(BeFalse())
				Expect(m.isNamespaceExcluded("kube-system")).To(BeFalse())
				Expect(m.isNamespaceExcluded("production")).To(BeFalse())
			})
		})

		Context("when only ExcludedNamespaces is set (blacklist mode)", func() {
			BeforeEach(func() {
				m.ExcludedNamespaces = map[string]bool{
					"kube-system": true,
					"kube-public": true,
				}
			})

			It("should exclude namespaces in the blacklist", func() {
				Expect(m.isNamespaceExcluded("kube-system")).To(BeTrue())
				Expect(m.isNamespaceExcluded("kube-public")).To(BeTrue())
			})

			It("should not exclude namespaces not in the blacklist", func() {
				Expect(m.isNamespaceExcluded("default")).To(BeFalse())
				Expect(m.isNamespaceExcluded("production")).To(BeFalse())
			})
		})

		Context("when only IncludedNamespaces is set (whitelist mode)", func() {
			BeforeEach(func() {
				m.IncludedNamespaces = map[string]bool{
					"staging":    true,
					"production": true,
				}
			})

			It("should not exclude namespaces in the whitelist", func() {
				Expect(m.isNamespaceExcluded("staging")).To(BeFalse())
				Expect(m.isNamespaceExcluded("production")).To(BeFalse())
			})

			It("should exclude namespaces not in the whitelist", func() {
				Expect(m.isNamespaceExcluded("default")).To(BeTrue())
				Expect(m.isNamespaceExcluded("kube-system")).To(BeTrue())
				Expect(m.isNamespaceExcluded("development")).To(BeTrue())
			})
		})

		Context("when both IncludedNamespaces and ExcludedNamespaces are set", func() {
			BeforeEach(func() {
				m.IncludedNamespaces = map[string]bool{
					"staging":    true,
					"production": true,
				}
				m.ExcludedNamespaces = map[string]bool{
					"kube-system": true,
					"staging":     true, // Intentionally overlap to test precedence
				}
			})

			It("should use whitelist mode (IncludedNamespaces takes precedence)", func() {
				// Whitelist mode: only staging and production are allowed
				Expect(m.isNamespaceExcluded("staging")).To(BeFalse())
				Expect(m.isNamespaceExcluded("production")).To(BeFalse())
				// All others are excluded, even if not in ExcludedNamespaces
				Expect(m.isNamespaceExcluded("default")).To(BeTrue())
				Expect(m.isNamespaceExcluded("kube-system")).To(BeTrue())
			})
		})
	})

	Describe("Handle with IncludedNamespaces (Issue #59)", func() {
		var m *PodMutator

		createAdmissionRequest := func(pod *corev1.Pod, namespace string) admission.Request {
			raw, err := json.Marshal(pod)
			Expect(err).NotTo(HaveOccurred())

			return admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:       "test-uid",
					Name:      pod.Name,
					Namespace: namespace,
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: raw,
					},
				},
			}
		}

		BeforeEach(func() {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				Build()

			m = &PodMutator{
				Client:  fakeClient,
				Decoder: decoder,
			}
		})

		Context("when pod is in an included namespace (whitelist mode)", func() {
			BeforeEach(func() {
				m.IncludedNamespaces = map[string]bool{
					"staging": true,
				}
			})

			It("should inject the scheduling gate", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "staging",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				req := createAdmissionRequest(pod, "staging")
				resp := m.Handle(ctx, req)

				Expect(resp.Allowed).To(BeTrue())
				// PatchResponseFromRaw returns patches, verify response has patch data
				// The patch adds scheduling gate and labels
				Expect(len(resp.Patches) > 0 || len(resp.Patch) > 0).To(BeTrue(), "expected patches to be applied")
			})
		})

		Context("when pod is not in an included namespace (whitelist mode)", func() {
			BeforeEach(func() {
				m.IncludedNamespaces = map[string]bool{
					"staging": true,
				}
			})

			It("should allow without injecting the gate", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				req := createAdmissionRequest(pod, "default")
				resp := m.Handle(ctx, req)

				Expect(resp.Allowed).To(BeTrue())
				Expect(resp.Result).NotTo(BeNil())
				Expect(resp.Result.Code).To(Equal(int32(http.StatusOK)))
				// No patches - gate was not injected
				Expect(resp.Patches).To(BeEmpty())
			})
		})

		Context("when IncludedNamespaces is empty (blacklist mode)", func() {
			BeforeEach(func() {
				m.ExcludedNamespaces = map[string]bool{
					"kube-system": true,
				}
			})

			It("should inject gate for non-excluded namespaces", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				req := createAdmissionRequest(pod, "default")
				resp := m.Handle(ctx, req)

				Expect(resp.Allowed).To(BeTrue())
				Expect(resp.Patches).NotTo(BeEmpty())
			})

			It("should not inject gate for excluded namespaces", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "kube-system",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				req := createAdmissionRequest(pod, "kube-system")
				resp := m.Handle(ctx, req)

				Expect(resp.Allowed).To(BeTrue())
				// No patches - namespace is excluded
				Expect(resp.Patches).To(BeEmpty())
			})
		})
	})

	Describe("allImagesExcluded", func() {
		var m *PodMutator

		BeforeEach(func() {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				Build()

			m = &PodMutator{
				Client:  fakeClient,
				Decoder: decoder,
			}
		})

		Context("when no images are excluded", func() {
			It("should return false", func() {
				pod := &corev1.Pod{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				Expect(m.allImagesExcluded(pod)).To(BeFalse())
			})
		})

		Context("when some images are excluded", func() {
			BeforeEach(func() {
				m.ExcludedImages = []string{"pause:latest"}
			})

			It("should return false if not all images are excluded", func() {
				pod := &corev1.Pod{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
							{Name: "sidecar", Image: "pause:latest"},
						},
					},
				}

				Expect(m.allImagesExcluded(pod)).To(BeFalse())
			})
		})

		Context("when all images are excluded", func() {
			BeforeEach(func() {
				m.ExcludedImages = []string{"pause:latest", "nginx:latest"}
			})

			It("should return true", func() {
				pod := &corev1.Pod{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
							{Name: "sidecar", Image: "pause:latest"},
						},
					},
				}

				Expect(m.allImagesExcluded(pod)).To(BeTrue())
			})
		})

		Context("when pod has init containers", func() {
			BeforeEach(func() {
				m.ExcludedImages = []string{"nginx:latest"}
			})

			It("should check init containers too", func() {
				pod := &corev1.Pod{
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{Name: "init", Image: "busybox:latest"},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				// busybox:latest is not excluded
				Expect(m.allImagesExcluded(pod)).To(BeFalse())
			})
		})
	})
})
