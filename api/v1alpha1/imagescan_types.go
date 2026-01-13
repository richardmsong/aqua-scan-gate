package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ImageScanSpec defines the desired state of ImageScan
type ImageScanSpec struct {
	// Image is the full image reference (e.g., registry.example.com/app:v1.2.3)
	// +kubebuilder:validation:Required
	Image string `json:"image"`

	// Digest is the image digest (sha256:...)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	Digest string `json:"digest"`

	// Registry is the source registry for the image
	// +optional
	Registry string `json:"registry,omitempty"`
}

// ScanPhase represents the current phase of the scan
// +kubebuilder:validation:Enum=Pending;InProgress;Registered;Failed;Error
type ScanPhase string

const (
	ScanPhasePending    ScanPhase = "Pending"
	ScanPhaseInProgress ScanPhase = "InProgress"
	ScanPhaseRegistered ScanPhase = "Registered"
	ScanPhaseFailed     ScanPhase = "Failed"
	ScanPhaseError      ScanPhase = "Error"
)

// VulnerabilitySummary contains counts of vulnerabilities by severity
type VulnerabilitySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// ImageScanStatus defines the observed state of ImageScan
type ImageScanStatus struct {
	// Phase is the current phase of the scan
	// +kubebuilder:default=Pending
	Phase ScanPhase `json:"phase,omitempty"`

	// AquaScanID is the ID returned by Aqua for this scan
	// +optional
	AquaScanID string `json:"aquaScanId,omitempty"`

	// LastScanTime is when the scan was last performed
	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// CompletedTime is when the scan reached a terminal state
	// +optional
	CompletedTime *metav1.Time `json:"completedTime,omitempty"`

	// Vulnerabilities contains the summary of found vulnerabilities
	// +optional
	Vulnerabilities *VulnerabilitySummary `json:"vulnerabilities,omitempty"`

	// Message provides additional details about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// RetryCount tracks the number of consecutive errors for exponential backoff
	// +optional
	RetryCount int `json:"retryCount,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.vulnerabilities.critical`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.status.vulnerabilities.high`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageScan is the Schema for the imagescans API
type ImageScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ImageScanSpec   `json:"spec,omitempty"`
	Status ImageScanStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageScanList contains a list of ImageScan
type ImageScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageScan `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageScan{}, &ImageScanList{})
}
