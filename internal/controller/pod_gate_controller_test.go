package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/richardmsong/aqua-scan-gate/api/v1alpha1"
	"github.com/richardmsong/aqua-scan-gate/pkg/imageref"
)

// mockResolver is a mock implementation for testing digest resolution
type mockResolver struct {
	digests map[string]string // image -> digest mapping
	errors  map[string]error  // image -> error mapping
}

func newMockResolver() *mockResolver {
	return &mockResolver{
		digests: make(map[string]string),
		errors:  make(map[string]error),
	}
}

func (m *mockResolver) ResolveImageRef(_ context.Context, img imageref.ImageRef) (imageref.ImageRef, error) {
	if img.Digest != "" {
		return img, nil
	}
	if err, ok := m.errors[img.Image]; ok {
		return img, err
	}
	if digest, ok := m.digests[img.Image]; ok {
		return imageref.ImageRef{
			Image:  img.Image,
			Digest: digest,
		}, nil
	}
	return img, nil
}

// Compile-time check that mockResolver implements ImageRefResolver
var _ ImageRefResolver = (*mockResolver)(nil)

var _ = Describe("PodGateReconciler", func() {
	var (
		scheme *runtime.Scheme
		ctx    context.Context
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(securityv1alpha1.AddToScheme(scheme)).To(Succeed())
		ctx = context.Background()
	})

	Describe("Reconcile", func() {
		Context("when all images are registered", func() {
			It("should remove the scheduling gate", func() {
				// Create a pod with our gate
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						SchedulingGates: []corev1.PodSchedulingGate{
							{Name: SchedulingGateName},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				// Create a registered ImageScan
				imageScan := &securityv1alpha1.ImageScan{
					ObjectMeta: metav1.ObjectMeta{
						Name:      imageref.ScanName(imageref.ImageRef{Image: "nginx:latest"}),
						Namespace: "default",
					},
					Spec: securityv1alpha1.ImageScanSpec{
						Image: "nginx:latest",
					},
					Status: securityv1alpha1.ImageScanStatus{
						Phase: securityv1alpha1.ScanPhaseRegistered,
					},
				}

				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					Build()

				r := &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "test-pod",
						Namespace: "default",
					},
				})
				Expect(err).NotTo(HaveOccurred())

				// Verify gate was removed
				var updatedPod corev1.Pod
				err = fakeClient.Get(ctx, types.NamespacedName{
					Name: "test-pod", Namespace: "default",
				}, &updatedPod)
				Expect(err).NotTo(HaveOccurred())
				Expect(hasSchedulingGate(&updatedPod, SchedulingGateName)).To(BeFalse())
			})
		})
	})

	Describe("mapImageScanToPods", func() {
		var (
			fakeClient client.Client
			r          *PodGateReconciler
		)

		// indexerFunc extracts scheduling gate names for the field indexer
		indexerFunc := func(obj client.Object) []string {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return nil
			}
			var gates []string
			for _, gate := range pod.Spec.SchedulingGates {
				gates = append(gates, gate.Name)
			}
			return gates
		}

		createPodWithGate := func(name, namespace, image string) *corev1.Pod {
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: corev1.PodSpec{
					SchedulingGates: []corev1.PodSchedulingGate{
						{Name: SchedulingGateName},
					},
					Containers: []corev1.Container{
						{Name: "app", Image: image},
					},
				},
			}
		}

		createPodWithoutGate := func(name, namespace, image string) *corev1.Pod {
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: image},
					},
				},
			}
		}

		createImageScan := func(name, namespace, image string, phase securityv1alpha1.ScanPhase) *securityv1alpha1.ImageScan {
			return &securityv1alpha1.ImageScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: securityv1alpha1.ImageScanSpec{
					Image: image,
				},
				Status: securityv1alpha1.ImageScanStatus{
					Phase: phase,
				},
			}
		}

		Context("when ImageScan is in Pending phase", func() {
			It("should return no requests", func() {
				pod := createPodWithGate("test-pod", "default", "nginx:latest")
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "nginx:latest"}),
					"default",
					"nginx:latest",
					securityv1alpha1.ScanPhasePending,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				Expect(requests).To(BeEmpty())
			})
		})

		Context("when ImageScan is in Registered phase", func() {
			It("should return requests for matching pods", func() {
				pod := createPodWithGate("test-pod", "default", "nginx:latest")
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "nginx:latest"}),
					"default",
					"nginx:latest",
					securityv1alpha1.ScanPhaseRegistered,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				Expect(requests).To(HaveLen(1))
				Expect(requests[0].Name).To(Equal("test-pod"))
				Expect(requests[0].Namespace).To(Equal("default"))
			})
		})

		Context("when ImageScan is in Error phase", func() {
			It("should return requests for matching pods", func() {
				pod := createPodWithGate("test-pod", "default", "nginx:latest")
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "nginx:latest"}),
					"default",
					"nginx:latest",
					securityv1alpha1.ScanPhaseError,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				Expect(requests).To(HaveLen(1))
				Expect(requests[0].Name).To(Equal("test-pod"))
				Expect(requests[0].Namespace).To(Equal("default"))
			})
		})

		Context("when pod is in excluded namespace", func() {
			It("should not return requests for pods in excluded namespaces", func() {
				pod := createPodWithGate("test-pod", "kube-system", "nginx:latest")
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "nginx:latest"}),
					"kube-system",
					"nginx:latest",
					securityv1alpha1.ScanPhaseRegistered,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client:             fakeClient,
					Scheme:             scheme,
					ExcludedNamespaces: map[string]bool{"kube-system": true},
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				Expect(requests).To(BeEmpty())
			})
		})

		Context("when pod does not have scheduling gate", func() {
			It("should not return requests for pods without our gate", func() {
				pod := createPodWithoutGate("test-pod", "default", "nginx:latest")
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "nginx:latest"}),
					"default",
					"nginx:latest",
					securityv1alpha1.ScanPhaseRegistered,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				Expect(requests).To(BeEmpty())
			})
		})

		Context("when ImageScan does not match any pod", func() {
			It("should return no requests", func() {
				pod := createPodWithGate("test-pod", "default", "nginx:latest")
				// ImageScan for a different image
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "redis:latest"}),
					"default",
					"redis:latest",
					securityv1alpha1.ScanPhaseRegistered,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				Expect(requests).To(BeEmpty())
			})
		})

		Context("when multiple pods reference the same image", func() {
			It("should return requests for all matching pods", func() {
				pod1 := createPodWithGate("test-pod-1", "default", "nginx:latest")
				pod2 := createPodWithGate("test-pod-2", "default", "nginx:latest")
				pod3 := createPodWithGate("test-pod-3", "other-ns", "nginx:latest")
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "nginx:latest"}),
					"default",
					"nginx:latest",
					securityv1alpha1.ScanPhaseRegistered,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod1, pod2, pod3, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				// Only pods in the same namespace as the ImageScan should match
				Expect(requests).To(HaveLen(2))
				names := []string{requests[0].Name, requests[1].Name}
				Expect(names).To(ContainElements("test-pod-1", "test-pod-2"))
			})
		})

		Context("when using ScanNamespace configuration", func() {
			It("should match pods to ImageScans in the configured namespace", func() {
				// Pod in "app" namespace, but ImageScans are created in "scans" namespace
				pod := createPodWithGate("test-pod", "app", "nginx:latest")
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "nginx:latest"}),
					"scans",
					"nginx:latest",
					securityv1alpha1.ScanPhaseRegistered,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client:        fakeClient,
					Scheme:        scheme,
					ScanNamespace: "scans",
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				Expect(requests).To(HaveLen(1))
				Expect(requests[0].Name).To(Equal("test-pod"))
				Expect(requests[0].Namespace).To(Equal("app"))
			})
		})

		Context("when passed a non-ImageScan object", func() {
			It("should return nil", func() {
				pod := createPodWithGate("test-pod", "default", "nginx:latest")

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				// Pass a Pod instead of an ImageScan
				requests := r.mapImageScanToPods(ctx, pod)
				Expect(requests).To(BeNil())
			})
		})

		Context("when pod has multiple containers with different images", func() {
			It("should match if any container image matches the ImageScan", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "multi-container-pod",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						SchedulingGates: []corev1.PodSchedulingGate{
							{Name: SchedulingGateName},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
							{Name: "sidecar", Image: "redis:latest"},
						},
					},
				}
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "redis:latest"}),
					"default",
					"redis:latest",
					securityv1alpha1.ScanPhaseRegistered,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				Expect(requests).To(HaveLen(1))
				Expect(requests[0].Name).To(Equal("multi-container-pod"))
			})
		})

		Context("when pod has init containers", func() {
			It("should match if init container image matches the ImageScan", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-with-init",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						SchedulingGates: []corev1.PodSchedulingGate{
							{Name: SchedulingGateName},
						},
						InitContainers: []corev1.Container{
							{Name: "init", Image: "busybox:latest"},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}
				imageScan := createImageScan(
					imageref.ScanName(imageref.ImageRef{Image: "busybox:latest"}),
					"default",
					"busybox:latest",
					securityv1alpha1.ScanPhaseRegistered,
				)

				fakeClient = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					WithIndex(&corev1.Pod{}, IndexFieldSchedulingGate, indexerFunc).
					Build()

				r = &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
				}

				requests := r.mapImageScanToPods(ctx, imageScan)
				Expect(requests).To(HaveLen(1))
				Expect(requests[0].Name).To(Equal("pod-with-init"))
			})
		})
	})

	Describe("Digest Resolution", func() {
		Context("when resolver is provided and image has no digest", func() {
			It("should resolve the digest and create ImageScan with resolved digest", func() {
				// Create a pod with our gate and a tag-based image
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						SchedulingGates: []corev1.PodSchedulingGate{
							{Name: SchedulingGateName},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod).
					Build()

				// Create mock resolver that returns a digest
				mockRes := newMockResolver()
				mockRes.digests["nginx:latest"] = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

				recorder := record.NewFakeRecorder(10)
				r := &PodGateReconciler{
					Client:   fakeClient,
					Scheme:   scheme,
					Recorder: recorder,
					Resolver: mockRes,
				}

				result, err := r.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "test-pod",
						Namespace: "default",
					},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(BeZero())

				// Verify ImageScan was created with the resolved digest
				var imageScanList securityv1alpha1.ImageScanList
				err = fakeClient.List(ctx, &imageScanList)
				Expect(err).NotTo(HaveOccurred())
				Expect(imageScanList.Items).To(HaveLen(1))
				Expect(imageScanList.Items[0].Spec.Digest).To(Equal("sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"))
			})
		})

		Context("when resolver returns an error", func() {
			It("should requeue and emit an event", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						SchedulingGates: []corev1.PodSchedulingGate{
							{Name: SchedulingGateName},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod).
					Build()

				// Create mock resolver that returns an error
				mockRes := newMockResolver()
				mockRes.errors["nginx:latest"] = fmt.Errorf("registry unreachable")

				recorder := record.NewFakeRecorder(10)
				r := &PodGateReconciler{
					Client:   fakeClient,
					Scheme:   scheme,
					Recorder: recorder,
					Resolver: mockRes,
				}

				result, err := r.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "test-pod",
						Namespace: "default",
					},
				})
				Expect(err).NotTo(HaveOccurred())
				// Should requeue after 30 seconds for transient errors
				Expect(result.RequeueAfter).To(BeNumerically(">", 0))

				// Verify no ImageScan was created
				var imageScanList securityv1alpha1.ImageScanList
				err = fakeClient.List(ctx, &imageScanList)
				Expect(err).NotTo(HaveOccurred())
				Expect(imageScanList.Items).To(BeEmpty())

				// Verify an event was emitted
				Eventually(recorder.Events).Should(Receive(ContainSubstring("DigestResolutionFailed")))
			})
		})

		Context("when resolver is nil", func() {
			It("should proceed without resolving digests", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						SchedulingGates: []corev1.PodSchedulingGate{
							{Name: SchedulingGateName},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod).
					Build()

				r := &PodGateReconciler{
					Client: fakeClient,
					Scheme: scheme,
					// No Resolver provided
				}

				_, err := r.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "test-pod",
						Namespace: "default",
					},
				})
				Expect(err).NotTo(HaveOccurred())

				// ImageScan should be created with empty digest
				var imageScanList securityv1alpha1.ImageScanList
				err = fakeClient.List(ctx, &imageScanList)
				Expect(err).NotTo(HaveOccurred())
				Expect(imageScanList.Items).To(HaveLen(1))
				Expect(imageScanList.Items[0].Spec.Digest).To(BeEmpty())
			})
		})

		Context("when image already has a digest", func() {
			It("should not call the resolver", func() {
				digestImage := "nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						SchedulingGates: []corev1.PodSchedulingGate{
							{Name: SchedulingGateName},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: digestImage},
						},
					},
				}

				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod).
					Build()

				// Create mock resolver that would fail if called
				mockRes := newMockResolver()
				mockRes.errors["nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"] = fmt.Errorf("should not be called")

				r := &PodGateReconciler{
					Client:   fakeClient,
					Scheme:   scheme,
					Resolver: mockRes,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "test-pod",
						Namespace: "default",
					},
				})
				Expect(err).NotTo(HaveOccurred())

				// ImageScan should be created with the original digest
				var imageScanList securityv1alpha1.ImageScanList
				err = fakeClient.List(ctx, &imageScanList)
				Expect(err).NotTo(HaveOccurred())
				Expect(imageScanList.Items).To(HaveLen(1))
				Expect(imageScanList.Items[0].Spec.Digest).To(Equal("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"))
			})
		})
	})
})
