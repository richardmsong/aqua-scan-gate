package controller

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/richardmsong/aqua-scan-triggerer/api/v1alpha1"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/aqua"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/tracing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	baseBackoff = 30 * time.Second
	maxBackoff  = 10 * time.Minute
)

// calculateBackoff returns an exponential backoff duration based on retry count.
// It uses multiplication (doubling) for clarity and caps at maxBackoff.
func calculateBackoff(retryCount int) time.Duration {
	backoff := baseBackoff
	for i := 0; i < retryCount && backoff < maxBackoff; i++ {
		backoff *= 2
	}
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	return backoff
}

// ImageScanReconciler reconciles a ImageScan object
type ImageScanReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	AquaClient     aqua.Client
	RescanInterval time.Duration
}

// +kubebuilder:rbac:groups=scans.aquasec.community,resources=imagescans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=scans.aquasec.community,resources=imagescans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=scans.aquasec.community,resources=imagescans/finalizers,verbs=update

func (r *ImageScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx, span := tracing.StartSpan(ctx, "ImageScanReconciler.Reconcile",
		trace.WithAttributes(
			attribute.String("imagescan.name", req.Name),
			attribute.String("imagescan.namespace", req.Namespace),
		),
	)
	defer span.End()

	logger := log.FromContext(ctx)

	var imageScan securityv1alpha1.ImageScan
	if err := r.Get(ctx, req.NamespacedName, &imageScan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Add image details to span
	span.SetAttributes(
		tracing.AttrImageName.String(imageScan.Spec.Image),
		tracing.AttrImageDigest.String(imageScan.Spec.Digest),
	)

	// Error state is terminal - don't attempt to reconcile
	if imageScan.Status.Phase == securityv1alpha1.ScanPhaseError {
		span.SetAttributes(tracing.AttrScanPhase.String(string(securityv1alpha1.ScanPhaseError)))
		logger.Info("ImageScan in error state, not reconciling",
			"image", imageScan.Spec.Image,
			"message", imageScan.Status.Message)
		return ctrl.Result{}, nil
	}

	// If already registered, no need to rescan
	if imageScan.Status.Phase == securityv1alpha1.ScanPhaseRegistered {
		span.SetAttributes(tracing.AttrScanPhase.String(string(securityv1alpha1.ScanPhaseRegistered)))
		return ctrl.Result{}, nil
	}

	// Check current scan status in Aqua
	// With v2 API: not 404 = image is scanned and ready
	result, err := r.AquaClient.GetScanResult(ctx, imageScan.Spec.Image, imageScan.Spec.Digest)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to get scan result from Aqua")
		logger.Error(err, "Failed to get scan result from Aqua")
		imageScan.Status.Phase = securityv1alpha1.ScanPhaseError
		imageScan.Status.Message = err.Error()
		imageScan.Status.RetryCount++
		if updateErr := r.Status().Update(ctx, &imageScan); updateErr != nil {
			logger.Error(updateErr, "Failed to update ImageScan status")
		}
		return ctrl.Result{RequeueAfter: calculateBackoff(imageScan.Status.RetryCount)}, nil
	}

	span.SetAttributes(tracing.AttrScanStatus.String(string(result.Status)))

	switch result.Status {
	case aqua.StatusNotFound:
		// Image not found in Aqua - trigger a new scan
		logger.Info("Image not found in Aqua, triggering scan", "image", imageScan.Spec.Image, "digest", imageScan.Spec.Digest)
		scanID, err := r.AquaClient.TriggerScan(ctx, imageScan.Spec.Image, imageScan.Spec.Digest)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to trigger scan")
			logger.Error(err, "Failed to trigger scan")
			imageScan.Status.Phase = securityv1alpha1.ScanPhaseError
			imageScan.Status.Message = err.Error()
			imageScan.Status.RetryCount++
			if updateErr := r.Status().Update(ctx, &imageScan); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{RequeueAfter: calculateBackoff(imageScan.Status.RetryCount)}, nil
		}
		span.SetAttributes(tracing.AttrScanID.String(scanID))
		imageScan.Status.Phase = securityv1alpha1.ScanPhasePending
		imageScan.Status.AquaScanID = scanID
		imageScan.Status.Message = "Scan triggered, waiting for Aqua to process"
		imageScan.Status.RetryCount = 0 // Reset retry count on success
		if updateErr := r.Status().Update(ctx, &imageScan); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		// Requeue immediately to check if the image has been registered
		return ctrl.Result{Requeue: true}, nil

	case aqua.StatusFound:
		// Image found in Aqua (not 404) - it's registered
		// Aqua Enforcer will handle actual enforcement
		now := metav1.Now()
		imageScan.Status.LastScanTime = &now
		imageScan.Status.CompletedTime = &now
		imageScan.Status.Phase = securityv1alpha1.ScanPhaseRegistered
		imageScan.Status.Message = "Image registered in Aqua"
		imageScan.Status.RetryCount = 0 // Reset retry count on success

		span.SetAttributes(tracing.AttrScanPhase.String(string(securityv1alpha1.ScanPhaseRegistered)))
		logger.Info("Image registered in Aqua",
			"image", imageScan.Spec.Image,
			"digest", imageScan.Spec.Digest)

		if updateErr := r.Status().Update(ctx, &imageScan); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *ImageScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ImageScan{}).
		Complete(r)
}
