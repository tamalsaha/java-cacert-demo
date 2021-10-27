package lib

import (
	"context"
	"crypto/x509"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	cacerts_api "kubeops.dev/csi-driver-cacerts/apis/cacerts/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CAProvider interface {
	GetCAs(obj client.Object, key string) ([]*x509.Certificate, error)
}

type ObjectRef struct {
	APIGroup  string `json:"apiGroup"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Key       string `json:"key,omitempty"`
}

func RefFrom(pc cacerts_api.CAProviderClass, ref cacerts_api.TypedObjectReference) ObjectRef {
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

func GetObj(c client.Client, mapper meta.RESTMapper, ref ObjectRef) (client.Object, error) {
	mapping, err := mapper.RESTMapping(ref.GroupKind())
	if err != nil {
		return nil, err
	}
	o, err := c.Scheme().New(mapping.GroupVersionKind)
	if err != nil {
		return nil, err
	}
	obj := o.(client.Object)
	err = c.Get(context.TODO(), ref.ObjKey(), obj)
	return obj, err
}
