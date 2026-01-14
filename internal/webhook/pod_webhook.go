package webhook

import (
	"context"
	"encoding/json"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/richardmsong/aqua-scan-triggerer/pkg/tracing"
)

const (
	SchedulingGateName   = "scans.aquasec.community/aqua-scan"
	AnnotationBypassScan = "scans.aquasec.community/bypass-scan"
)

// PodMutator adds scheduling gate to pods
type PodMutator struct {
	Client  client.Client
	decoder admission.Decoder

	// ExcludedNamespaces won't have the gate added
	ExcludedNamespaces map[string]bool

	// ExcludedImages won't trigger gating (e.g., known-safe images)
	ExcludedImages []string
}

// +kubebuilder:webhook:path=/mutate-v1-pod,mutating=true,failurePolicy=fail,sideEffects=None,groups="",resources=pods,verbs=create,versions=v1,name=mpod.scans.aquasec.community,admissionReviewVersions=v1

func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	ctx, span := tracing.StartSpan(ctx, "PodMutator.Handle",
		trace.WithAttributes(
			tracing.AttrPodName.String(req.Name),
			tracing.AttrPodNamespace.String(req.Namespace),
			attribute.String("operation", string(req.Operation)),
		),
	)
	defer span.End()

	logger := log.FromContext(ctx)

	pod := &corev1.Pod{}
	if err := m.decoder.Decode(req, pod); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to decode pod")
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Skip excluded namespaces
	if m.ExcludedNamespaces[req.Namespace] {
		span.SetAttributes(attribute.Bool("excluded_namespace", true))
		logger.V(1).Info("Skipping excluded namespace", "namespace", req.Namespace)
		return admission.Allowed("excluded namespace")
	}

	// Skip if bypass annotation is set
	if pod.Annotations != nil && pod.Annotations[AnnotationBypassScan] == "true" {
		span.SetAttributes(attribute.Bool("bypassed", true))
		logger.Info("Bypass annotation found, skipping gate injection", "pod", pod.Name)
		return admission.Allowed("bypass annotation")
	}

	// Skip pods that already have our gate
	for _, gate := range pod.Spec.SchedulingGates {
		if gate.Name == SchedulingGateName {
			span.SetAttributes(attribute.Bool("gate_already_present", true))
			return admission.Allowed("gate already present")
		}
	}

	// Check if all images are excluded
	if m.allImagesExcluded(pod) {
		span.SetAttributes(attribute.Bool("all_images_excluded", true))
		logger.V(1).Info("All images excluded, skipping gate injection", "pod", pod.Name)
		return admission.Allowed("all images excluded")
	}

	// Add our scheduling gate
	span.SetAttributes(attribute.Bool("gate_injected", true))
	logger.Info("Adding scheduling gate", "pod", pod.Name, "namespace", req.Namespace)
	pod.Spec.SchedulingGates = append(pod.Spec.SchedulingGates, corev1.PodSchedulingGate{
		Name: SchedulingGateName,
	})

	// Ensure labels exist for tracking
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels["scans.aquasec.community/gated"] = "true"

	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to marshal pod")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func (m *PodMutator) allImagesExcluded(pod *corev1.Pod) bool {
	if len(m.ExcludedImages) == 0 {
		return false
	}

	excludedSet := make(map[string]bool)
	for _, img := range m.ExcludedImages {
		excludedSet[img] = true
	}

	for _, c := range pod.Spec.InitContainers {
		if !excludedSet[c.Image] {
			return false
		}
	}
	for _, c := range pod.Spec.Containers {
		if !excludedSet[c.Image] {
			return false
		}
	}

	return true
}

func (m *PodMutator) InjectDecoder(d admission.Decoder) error {
	m.decoder = d
	return nil
}
