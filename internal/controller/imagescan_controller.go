package controller

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/richardmsong/aqua-scan-triggerer/api/v1alpha1"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/aqua"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
	logger := log.FromContext(ctx)

	var imageScan securityv1alpha1.ImageScan
	if err := r.Get(ctx, req.NamespacedName, &imageScan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If already in terminal state, check if rescan is needed
	if imageScan.Status.Phase == securityv1alpha1.ScanPhaseRegistered ||
		imageScan.Status.Phase == securityv1alpha1.ScanPhaseFailed {

		// Optionally rescan after interval
		if r.RescanInterval > 0 && imageScan.Status.CompletedTime != nil {
			elapsed := time.Since(imageScan.Status.CompletedTime.Time)
			if elapsed >= r.RescanInterval {
				logger.Info("Triggering rescan due to interval", "image", imageScan.Spec.Image)
				imageScan.Status.Phase = securityv1alpha1.ScanPhasePending
				imageScan.Status.Message = "Rescan triggered"
				if updateErr := r.Status().Update(ctx, &imageScan); updateErr != nil {
					logger.Error(updateErr, "Failed to update ImageScan status for rescan")
					return ctrl.Result{}, updateErr
				}
			} else {
				// Requeue for when rescan is due
				return ctrl.Result{RequeueAfter: r.RescanInterval - elapsed}, nil
			}
		} else {
			return ctrl.Result{}, nil
		}
	}

	// Check current scan status in Aqua
	// With v2 API: not 404 = image is scanned and ready
	result, err := r.AquaClient.GetScanResult(ctx, imageScan.Spec.Image, imageScan.Spec.Digest)
	if err != nil {
		logger.Error(err, "Failed to get scan result from Aqua")
		imageScan.Status.Phase = securityv1alpha1.ScanPhaseError
		imageScan.Status.Message = err.Error()
		if updateErr := r.Status().Update(ctx, &imageScan); updateErr != nil {
			logger.Error(updateErr, "Failed to update ImageScan status")
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	switch result.Status {
	case aqua.StatusNotFound:
		// Image not found in Aqua - trigger a new scan
		logger.Info("Image not found in Aqua, triggering scan", "image", imageScan.Spec.Image, "digest", imageScan.Spec.Digest)
		scanID, err := r.AquaClient.TriggerScan(ctx, imageScan.Spec.Image, imageScan.Spec.Digest)
		if err != nil {
			logger.Error(err, "Failed to trigger scan")
			imageScan.Status.Phase = securityv1alpha1.ScanPhaseError
			imageScan.Status.Message = err.Error()
		} else {
			imageScan.Status.Phase = securityv1alpha1.ScanPhaseInProgress
			imageScan.Status.AquaScanID = scanID
			imageScan.Status.Message = "Scan triggered, waiting for Aqua to process"
		}
		if updateErr := r.Status().Update(ctx, &imageScan); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		// Requeue to check if the scan has been processed
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil

	case aqua.StatusFound:
		// Image found in Aqua (not 404) - it's registered
		// Aqua Enforcer will handle actual enforcement
		now := metav1.Now()
		imageScan.Status.LastScanTime = &now
		imageScan.Status.CompletedTime = &now
		imageScan.Status.Phase = securityv1alpha1.ScanPhaseRegistered
		imageScan.Status.Message = "Image registered in Aqua"

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
