package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretKeySelector points at one key of an existing Kubernetes Secret.
type SecretKeySelector struct {
	// Name of the Secret.
	Name string `json:"name"`
	// Key within the Secret's data. Defaults to "token".
	// +kubebuilder:default=token
	// +optional
	Key string `json:"key,omitempty"`
}

// KeyorixSecretData maps one Keyorix secret reference to a key in the target Secret.
type KeyorixSecretData struct {
	// SecretKey is the key to set in the target Kubernetes Secret.
	SecretKey string `json:"secretKey"`
	// Ref is the Keyorix "project/environment/name" reference to read (ADR-059).
	Ref string `json:"ref"`
}

// KeyorixSecretTarget describes the Kubernetes Secret to create/maintain.
type KeyorixSecretTarget struct {
	// Name of the target Secret. Defaults to the KeyorixSecret's own name.
	// +optional
	Name string `json:"name,omitempty"`
	// Type of the target Secret. Defaults to Opaque.
	// +kubebuilder:default=Opaque
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`
}

// KeyorixSecretSpec defines which Keyorix secrets to sync and where.
type KeyorixSecretSpec struct {
	// Server is the Keyorix base URL, e.g. https://keyorix.internal. Must be https (the
	// machine-identity token is sent as a bearer header) AND must match the operator's
	// --allowed-servers list — the operator rejects any other destination.
	// +kubebuilder:validation:Pattern=`^https://`
	Server string `json:"server"`
	// TokenSecretRef sources the Keyorix machine-identity token (a least-privilege
	// identity with secrets.read on the referenced secrets). The token is never
	// inlined in the spec.
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef"`
	// RefreshInterval is how often to re-read values from Keyorix. Defaults to 5m.
	// +optional
	RefreshInterval *metav1.Duration `json:"refreshInterval,omitempty"`
	// Target is the Kubernetes Secret to create/maintain.
	// +optional
	Target KeyorixSecretTarget `json:"target,omitempty"`
	// Data lists the Keyorix references to materialise into the target Secret.
	// +kubebuilder:validation:MinItems=1
	Data []KeyorixSecretData `json:"data"`
}

// KeyorixSecretStatus reports the last reconcile outcome.
type KeyorixSecretStatus struct {
	// Conditions holds the Ready condition (reason SyncError when a sync fails).
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// LastSyncTime is when the target Secret was last successfully written.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// SyncedHash is a fingerprint of the last successfully-written data, so an
	// unchanged reconcile is a no-op.
	// +optional
	SyncedHash string `json:"syncedHash,omitempty"`
	// ObservedGeneration is the spec generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=kxsecret
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.target.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`

// KeyorixSecret materialises selected Keyorix secrets into a native Kubernetes
// Secret and keeps it current as upstream values rotate.
type KeyorixSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeyorixSecretSpec   `json:"spec,omitempty"`
	Status KeyorixSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeyorixSecretList is a list of KeyorixSecret.
type KeyorixSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeyorixSecret `json:"items"`
}
