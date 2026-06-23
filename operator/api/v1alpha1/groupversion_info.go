// Package v1alpha1 contains the API types for the Keyorix operator's
// secrets.keyorix.io group. A KeyorixSecret declares which Keyorix secrets to
// materialise into a native Kubernetes Secret and keeps it current.
//
// +kubebuilder:object:generate=true
// +groupName=secrets.keyorix.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the group/version for this API.
var GroupVersion = schema.GroupVersion{Group: "secrets.keyorix.io", Version: "v1alpha1"}

// SchemeBuilder registers this API's types with a runtime.Scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds this API's types to a runtime.Scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &KeyorixSecret{}, &KeyorixSecretList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
