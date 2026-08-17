package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretKeySelector points at one key of an existing Kubernetes Secret.
type SecretKeySelector struct {
	// Name of the Secret. Bounded like KeyorixSecretTarget.Name (a Kubernetes object
	// name can never legitimately exceed this) so an oversized value can't inflate a
	// validateServer-style error message embedding it past the Condition.message
	// 32768-char cap (r143's rationale for Ref/Target.Name, applied here too).
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// Key within the Secret's data. Defaults to "token". Bounded for the same reason
	// as Name above.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default=token
	// +optional
	Key string `json:"key,omitempty"`
}

// KeyorixSecretData maps one Keyorix secret reference to a key in the target Secret.
type KeyorixSecretData struct {
	// SecretKey is the key to set in the target Kubernetes Secret. Must be a valid
	// Kubernetes Secret data key: alphanumeric, dash, dot, or underscore (K8SSYNC-001).
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	SecretKey string `json:"secretKey"`
	// Ref is the Keyorix "project/environment/name" reference to read (ADR-059).
	// Bounded well above any realistic project/environment/name combination (the main
	// module caps individual project/environment names at 200 chars each — see
	// maxProjectNameLen/maxEnvironmentNameLen in internal/core/catalog.go) but far below
	// unbounded, so a CR author can't inflate a single reconcile's request/response size
	// with an arbitrarily long string (r143).
	// +kubebuilder:validation:MaxLength=512
	Ref string `json:"ref"`
}

// KeyorixSecretTarget describes the Kubernetes Secret to create/maintain.
type KeyorixSecretTarget struct {
	// Name of the target Secret. Defaults to the KeyorixSecret's own name. Must be a
	// valid Kubernetes RFC1123 DNS subdomain (K8SSYNC-002).
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +kubebuilder:validation:MaxLength=253
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
	// --allowed-servers list — the operator rejects any other destination. Bounded like
	// every other CR-controlled string in this API (Ref at 512, Target.Name at 253):
	// an oversized value here is echoed verbatim into validateServer's rejection
	// message, which reconcile writes into the Ready condition's Message — capped at
	// 32768 chars by the generated CRD's own Condition schema. An unbounded Server
	// could exceed that cap, making the status subresource write itself fail
	// validation and masking the real error behind a stuck, stale Ready condition.
	// 2048 comfortably covers any real URL while staying far below the 32768 cap.
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https://`
	Server string `json:"server"`
	// TokenSecretRef sources the Keyorix machine-identity token (a least-privilege
	// identity with secrets.read on the referenced secrets). The token is never
	// inlined in the spec. The referenced Secret MUST carry the label
	// secrets.keyorix.io/token-secret=true, set by whoever creates it (a principal
	// with real Secret-write RBAC) — the operator refuses to resolve an unlabeled
	// Secret, so a namespace-scoped KeyorixSecret author with no core-Secret RBAC of
	// their own cannot point this at an arbitrary pre-existing Secret and have the
	// operator ship its bytes to the Keyorix server as a bearer token.
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef"`
	// RefreshInterval is how often to re-read values from Keyorix. Defaults to 5m.
	// +optional
	RefreshInterval *metav1.Duration `json:"refreshInterval,omitempty"`
	// Target is the Kubernetes Secret to create/maintain.
	// +optional
	Target KeyorixSecretTarget `json:"target,omitempty"`
	// Data lists the Keyorix references to materialise into the target Secret.
	// MaxItems bounds per-reconcile fan-out (r143): buildDesired fetches every entry
	// sequentially over HTTP (internal/keyorix.Client, 30s timeout per call) while
	// SetupWithManager runs reconciles on a small, fixed worker pool shared across every
	// namespace in the cluster — an unbounded array from any single, least-privileged,
	// CR-create-capable tenant could otherwise stall a shared worker for an unbounded
	// time, starving reconciliation of every other tenant's KeyorixSecret. 50 mirrors
	// this codebase's existing bulk-operation cap (maxEnvNamesPerCreate in
	// internal/core/catalog.go) — comfortably enough keys for one Kubernetes Secret
	// (which itself caps out around 1MiB total) while keeping worst-case per-reconcile
	// fan-out in the tens, not thousands.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=50
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
	// LastTargetName is the target Secret name materialised by the most recent
	// successful sync. spec.target.name is mutable — when it changes, the Secret
	// previously created under this OLD name would otherwise never be revisited by any
	// later reconcile (Reconcile only ever looks at the CURRENT secretName) and would
	// linger in the cluster indefinitely with its last-synced, possibly since-rotated,
	// plaintext value. Reconcile compares this field against the current target name on
	// every pass and wipes the orphaned Secret under the old name before proceeding.
	// +optional
	LastTargetName string `json:"lastTargetName,omitempty"`
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
