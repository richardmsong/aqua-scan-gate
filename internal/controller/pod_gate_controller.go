package controller

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/richardmsong/aqua-scan-triggerer/api/v1alpha1"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/imageref"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/tracing"
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

	// IndexFieldSchedulingGate is the field name for the scheduling gate index
	IndexFieldSchedulingGate = "spec.schedulingGates.name"
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
	ctx, span := tracing.StartSpan(ctx, "PodGateReconciler.Reconcile",
		trace.WithAttributes(
			tracing.AttrPodName.String(req.Name),
			tracing.AttrPodNamespace.String(req.Namespace),
		),
	)
	defer span.End()

	logger := log.FromContext(ctx)

	// Skip excluded namespaces
	if r.ExcludedNamespaces[req.Namespace] {
		span.SetAttributes(attribute.Bool("excluded_namespace", true))
		return ctrl.Result{}, nil
	}

	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Skip if pod doesn't have our gate
	if !hasSchedulingGate(&pod, SchedulingGateName) {
		span.SetAttributes(attribute.Bool("has_scheduling_gate", false))
		return ctrl.Result{}, nil
	}

	span.SetAttributes(attribute.Bool("has_scheduling_gate", true))

	// Check for bypass annotation
	if pod.Annotations != nil && pod.Annotations[AnnotationBypassScan] == "true" {
		span.SetAttributes(attribute.Bool("bypassed", true))
		logger.Info("Bypass annotation found, removing gate", "pod", pod.Name)
		removeSchedulingGate(&pod, SchedulingGateName)
		if err := r.Update(ctx, &pod); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to update pod")
			return ctrl.Result{}, err
		}
		if r.Recorder != nil {
			r.Recorder.Event(&pod, corev1.EventTypeWarning, "ScanBypassed", "Security scan bypassed via annotation")
		}
		return ctrl.Result{}, nil
	}

	// Extract all images from pod spec
	images := imageref.ExtractFromPod(&pod)
	span.SetAttributes(attribute.Int("image_count", len(images)))

	if len(images) == 0 {
		logger.Info("No images found in pod, removing gate", "pod", pod.Name)
		removeSchedulingGate(&pod, SchedulingGateName)
		return ctrl.Result{}, r.Update(ctx, &pod)
	}

	// Check/create ImageScan for each image
	allPassed := true
	var pendingImages []string

	for _, img := range images {
		imageCtx, imageSpan := tracing.StartSpan(ctx, "CheckImageScan",
			trace.WithAttributes(
				tracing.AttrImageName.String(img.Image),
				tracing.AttrImageDigest.String(img.Digest),
			),
		)

		scanName := imageref.ScanName(img)
		scanNamespace := r.ScanNamespace
		if scanNamespace == "" {
			scanNamespace = pod.Namespace
		}

		var imageScan securityv1alpha1.ImageScan
		err := r.Get(imageCtx, types.NamespacedName{
			Name:      scanName,
			Namespace: scanNamespace,
		}, &imageScan)

		if apierrors.IsNotFound(err) {
			// Create ImageScan CR
			imageSpan.SetAttributes(attribute.Bool("created_new_scan", true))
			logger.Info("Creating ImageScan", "image", img.Image, "name", scanName)
			imageScan = securityv1alpha1.ImageScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      scanName,
					Namespace: scanNamespace,
					Labels: map[string]string{
						"security.example.com/image-hash": imageref.HashString(img.Image)[:16],
					},
				},
				Spec: securityv1alpha1.ImageScanSpec{
					Image:  img.Image,
					Digest: img.Digest,
				},
			}
			if err := r.Create(imageCtx, &imageScan); err != nil {
				if !apierrors.IsAlreadyExists(err) {
					imageSpan.RecordError(err)
					imageSpan.SetStatus(codes.Error, "Failed to create ImageScan")
					logger.Error(err, "Failed to create ImageScan")
					imageSpan.End()
					return ctrl.Result{}, err
				}
			}
			allPassed = false
			pendingImages = append(pendingImages, img.Image)
			imageSpan.End()
			continue
		} else if err != nil {
			imageSpan.RecordError(err)
			imageSpan.SetStatus(codes.Error, "Failed to get ImageScan")
			logger.Error(err, "Failed to get ImageScan")
			imageSpan.End()
			return ctrl.Result{}, err
		}

		// Check scan status
		imageSpan.SetAttributes(tracing.AttrScanPhase.String(string(imageScan.Status.Phase)))
		switch imageScan.Status.Phase {
		case securityv1alpha1.ScanPhaseRegistered:
			// Good, continue checking other images
			imageSpan.End()
			continue
		case securityv1alpha1.ScanPhaseError:
			// Error occurred - don't remove gate, emit event
			if r.Recorder != nil {
				r.Recorder.Eventf(&pod, corev1.EventTypeWarning, "ScanError",
					"Image %s scan error: %s", img.Image, imageScan.Status.Message)
			}
			allPassed = false
			pendingImages = append(pendingImages, img.Image)
		default:
			// Still pending
			allPassed = false
			pendingImages = append(pendingImages, img.Image)
		}
		imageSpan.End()
	}

	span.SetAttributes(
		attribute.Bool("all_passed", allPassed),
		attribute.Int("pending_images_count", len(pendingImages)),
	)

	if allPassed {
		logger.Info("All images passed scan, removing gate", "pod", pod.Name)
		removeSchedulingGate(&pod, SchedulingGateName)
		if err := r.Update(ctx, &pod); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to update pod")
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

	// No requeue needed - ImageScan watch will trigger reconciliation
	return ctrl.Result{}, nil
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

func (r *PodGateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Set up field indexer for efficient pod listing by scheduling gate
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&corev1.Pod{},
		IndexFieldSchedulingGate,
		func(obj client.Object) []string {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return nil
			}
			var gates []string
			for _, gate := range pod.Spec.SchedulingGates {
				gates = append(gates, gate.Name)
			}
			return gates
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer: %w", err)
	}

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
		Watches(
			&securityv1alpha1.ImageScan{},
			handler.EnqueueRequestsFromMapFunc(r.mapImageScanToPods),
		).
		Complete(r)
}

// mapImageScanToPods maps ImageScan changes to pods that reference the same image.
// This enables efficient event-driven reconciliation instead of polling.
func (r *PodGateReconciler) mapImageScanToPods(ctx context.Context, obj client.Object) []reconcile.Request {
	imageScan, ok := obj.(*securityv1alpha1.ImageScan)
	if !ok {
		return nil
	}

	logger := log.FromContext(ctx)

	// Only trigger reconciliation for terminal states (Registered or Error)
	if imageScan.Status.Phase != securityv1alpha1.ScanPhaseRegistered &&
		imageScan.Status.Phase != securityv1alpha1.ScanPhaseError {
		return nil
	}

	// List only pods with our scheduling gate using the field indexer
	var podList corev1.PodList
	if err := r.List(ctx, &podList, client.MatchingFields{
		IndexFieldSchedulingGate: SchedulingGateName,
	}); err != nil {
		logger.Error(err, "Failed to list pods for ImageScan mapping")
		return nil
	}

	var requests []reconcile.Request
	for _, pod := range podList.Items {
		// Skip excluded namespaces
		if r.ExcludedNamespaces[pod.Namespace] {
			continue
		}

		// Check if this pod references the image from this ImageScan
		images := imageref.ExtractFromPod(&pod)
		for _, img := range images {
			scanName := imageref.ScanName(img)
			scanNamespace := r.ScanNamespace
			if scanNamespace == "" {
				scanNamespace = pod.Namespace
			}

			// Match by name and namespace
			if scanName == imageScan.Name && scanNamespace == imageScan.Namespace {
				logger.V(1).Info("Mapping ImageScan to pod",
					"imageScan", imageScan.Name,
					"pod", pod.Name,
					"namespace", pod.Namespace)
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
				})
				break // Pod already added, no need to check other images
			}
		}
	}

	return requests
}
