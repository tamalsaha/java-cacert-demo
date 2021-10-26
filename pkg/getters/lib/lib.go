package lib

import (
	"context"
	"crypto/x509"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	cacerts_api "kubeops.dev/csi-driver-cacerts/apis/cacerts/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sync"
)

type CAGetter interface {
	GetCAs(obj client.Object, key string) ([]*x509.Certificate, error)
}

//// issuerConstructor constructs an issuer given an Issuer resource and a Context.
//// An error will be returned if the appropriate issuer is not registered.
//type IssuerConstructor func(*controller.Context, v1.GenericIssuer) (Interface, error)

var (
	constructors     = make(map[string]CAGetter)
	constructorsLock sync.RWMutex
)

// Register will register an issuer constructor so it can be used within the
// application. 'name' should be unique, and should be used to identify this
// issuer.
// TODO: move this method to be on Factory, and invent a way to obtain a
// SharedFactory. This will make testing easier.
func RegisterIssuer(name string, c CAGetter) {
	constructorsLock.Lock()
	defer constructorsLock.Unlock()
	constructors[name] = c
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

func (ref ObjectRef) ObjKey() client.ObjectKey {
	return client.ObjectKey{
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
