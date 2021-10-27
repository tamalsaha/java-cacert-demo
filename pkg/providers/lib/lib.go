package lib

import (
	"context"
	"crypto/x509"
	"k8s.io/apimachinery/pkg/api/meta"
	cacerts_api "kubeops.dev/csi-driver-cacerts/apis/cacerts/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CAProvider interface {
	GetCAs(obj client.Object, key string) ([]*x509.Certificate, error)
}

func GetObj(c client.Client, mapper meta.RESTMapper, ref cacerts_api.ObjectRef) (client.Object, error) {
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
