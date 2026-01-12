package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/richardmsong/aqua-scan-triggerer/api/v1alpha1"
)

const (
	// SchedulingGateName is the name of our scheduling gate
	SchedulingGateName = "scans.aquasec.community/aqua-scan"

	// AnnotationScanStatus stores comma-separated image scan statuses
	AnnotationScanStatus = "scans.aquasec.community/scan-status"

	// AnnotationBypassScan allows bypassing the scan gate
	AnnotationBypassScan = "scans.aquasec.community/bypass-scan"

	// LabelManagedBy identifies pods managed by this controller
	LabelManagedBy = "scans.aquasec.community/managed-by"
)

// PodGateReconciler reconciles Pods with our scheduling gate
type PodGateReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	// Namespace where ImageScan CRs are created (empty = same as pod)
	ScanNamespace string
	// Namespaces to exclude from scanning
	ExcludedNamespaces map[string]bool
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=scans.aquasec.community,resources=imagescans,verbs=get;list;watch;create

func (r *PodGateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Skip excluded namespaces
	if r.ExcludedNamespaces[req.Namespace] {
		return ctrl.Result{}, nil
	}

	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Skip if pod doesn't have our gate
	if !hasSchedulingGate(&pod, SchedulingGateName) {
		return ctrl.Result{}, nil
	}

	// Check for bypass annotation
	if pod.Annotations != nil && pod.Annotations[AnnotationBypassScan] == "true" {
		logger.Info("Bypass annotation found, removing gate", "pod", pod.Name)
		removeSchedulingGate(&pod, SchedulingGateName)
		if err := r.Update(ctx, &pod); err != nil {
			return ctrl.Result{}, err
		}
		if r.Recorder != nil {
			r.Recorder.Event(&pod, corev1.EventTypeWarning, "ScanBypassed", "Security scan bypassed via annotation")
		}
		return ctrl.Result{}, nil
	}

	// Extract all images from pod spec
	images := extractImages(&pod)
	if len(images) == 0 {
		logger.Info("No images found in pod, removing gate", "pod", pod.Name)
		removeSchedulingGate(&pod, SchedulingGateName)
		return ctrl.Result{}, r.Update(ctx, &pod)
	}

	// Check/create ImageScan for each image
	allPassed := true
	var pendingImages []string

	for _, img := range images {
		scanName := imageScanName(img)
		scanNamespace := r.ScanNamespace
		if scanNamespace == "" {
			scanNamespace = pod.Namespace
		}

		var imageScan securityv1alpha1.ImageScan
		err := r.Get(ctx, types.NamespacedName{
			Name:      scanName,
			Namespace: scanNamespace,
		}, &imageScan)

		if apierrors.IsNotFound(err) {
			// Create ImageScan CR
			logger.Info("Creating ImageScan", "image", img.image, "name", scanName)
			imageScan = securityv1alpha1.ImageScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      scanName,
					Namespace: scanNamespace,
					Labels: map[string]string{
						"security.example.com/image-hash": hashString(img.image)[:16],
					},
				},
				Spec: securityv1alpha1.ImageScanSpec{
					Image:  img.image,
					Digest: img.digest,
				},
			}
			if err := r.Create(ctx, &imageScan); err != nil {
				if !apierrors.IsAlreadyExists(err) {
					logger.Error(err, "Failed to create ImageScan")
					return ctrl.Result{}, err
				}
			}
			allPassed = false
			pendingImages = append(pendingImages, img.image)
			continue
		} else if err != nil {
			logger.Error(err, "Failed to get ImageScan")
			return ctrl.Result{}, err
		}

		// Check scan status
		switch imageScan.Status.Phase {
		case securityv1alpha1.ScanPhaseRegistered:
			// Good, continue checking other images
			continue
		case securityv1alpha1.ScanPhaseFailed:
			// Scan failed - don't remove gate, emit event
			if r.Recorder != nil {
				r.Recorder.Eventf(&pod, corev1.EventTypeWarning, "ScanFailed",
					"Image %s failed security scan: %s", img.image, imageScan.Status.Message)
			}
			allPassed = false
		default:
			// Still pending
			allPassed = false
			pendingImages = append(pendingImages, img.image)
		}
	}

	if allPassed {
		logger.Info("All images passed scan, removing gate", "pod", pod.Name)
		removeSchedulingGate(&pod, SchedulingGateName)
		if err := r.Update(ctx, &pod); err != nil {
			return ctrl.Result{}, err
		}
		if r.Recorder != nil {
			r.Recorder.Event(&pod, corev1.EventTypeNormal, "ScanPassed", "All images passed security scan")
		}
		return ctrl.Result{}, nil
	}

	if len(pendingImages) > 0 && r.Recorder != nil {
		r.Recorder.Eventf(&pod, corev1.EventTypeNormal, "ScanPending",
			"Waiting for scan to complete for: %s", strings.Join(pendingImages, ", "))
	}

	// Requeue to check again
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

type imageRef struct {
	image  string
	digest string
}

func extractImages(pod *corev1.Pod) []imageRef {
	var images []imageRef
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

		images = append(images, imageRef{
			image:  image,
			digest: digest,
		})
	}

	for _, c := range pod.Spec.InitContainers {
		addImage(c.Image)
	}
	for _, c := range pod.Spec.Containers {
		addImage(c.Image)
	}
	for _, c := range pod.Spec.EphemeralContainers {
		addImage(c.Image)
	}

	return images
}

func hasSchedulingGate(pod *corev1.Pod, gateName string) bool {
	for _, gate := range pod.Spec.SchedulingGates {
		if gate.Name == gateName {
			return true
		}
	}
	return false
}

func removeSchedulingGate(pod *corev1.Pod, gateName string) {
	var filtered []corev1.PodSchedulingGate
	for _, gate := range pod.Spec.SchedulingGates {
		if gate.Name != gateName {
			filtered = append(filtered, gate)
		}
	}
	pod.Spec.SchedulingGates = filtered
}

func imageScanName(img imageRef) string {
	// Use digest if available, otherwise hash the image reference
	if img.digest != "" {
		// sha256:abc123... -> sha256-abc123...
		return strings.ReplaceAll(img.digest, ":", "-")[:63]
	}
	return fmt.Sprintf("img-%s", hashString(img.image)[:56])
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

func (r *PodGateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return false
			}
			// Only reconcile pods with our gate
			return hasSchedulingGate(pod, SchedulingGateName)
		})).
		Complete(r)
}
