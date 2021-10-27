package v1alpha1

import (
	"kubeops.dev/csi-driver-cacerts/crds"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"kmodules.xyz/client-go/apiextensions"
)

func (_ CAProviderClass) CustomResourceDefinition() *apiextensions.CustomResourceDefinition {
	return crds.MustCustomResourceDefinition(SchemeGroupVersion.WithResource(ResourceCAProviderClasses))
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ObjectRef struct {
	APIGroup  string `json:"apiGroup"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Key       string `json:"key,omitempty"`
}

func RefFrom(pc CAProviderClass, ref TypedObjectReference) ObjectRef {
	result := ObjectRef{
		APIGroup:  "",
		Kind:      ref.Kind,
		Namespace: ref.Namespace,
		Name:      ref.Name,
		Key:       ref.Key,
	}
	if ref.APIGroup != nil {
		result.APIGroup = *ref.APIGroup
	} else {
		result.APIGroup = "v1"
	}
	if result.Namespace == "" {
		result.Namespace = pc.Namespace
	}
	return result
}

func (ref ObjectRef) GroupKind() schema.GroupKind {
	return schema.GroupKind{Group: ref.APIGroup, Kind: ref.Kind}
}

func (ref ObjectRef) ObjKey() types.NamespacedName {
	return types.NamespacedName{
		Namespace: ref.Namespace,
		Name:      ref.Name,
	}
}
