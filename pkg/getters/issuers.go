package getters

import (
	"fmt"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/tamalsaha/java-cacert-demo/pkg/getters/lib"
	"github.com/tamalsaha/java-cacert-demo/pkg/getters/providers"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCAGetter(c client.Client, ref lib.ObjectRef, obj client.Object) (lib.CAGetter, error) {
	switch ref.GVK() {
	case corev1.SchemeGroupVersion.WithKind("Secret"):
		return new(providers.CAGetterSecret), nil
	case cmapi.SchemeGroupVersion.WithKind("Issuer"),
		cmapi.SchemeGroupVersion.WithKind("ClusterIssuer"):
		issuer, ok := obj.(cmapi.GenericIssuer)
		if !ok {
			return nil, fmt.Errorf("unknow obj ref %+v", ref)
		}
		if issuer.GetSpec().CA != nil {
			return &providers.CAGetterIssuer{Reader: c}, nil
		}
	}
	return nil, fmt.Errorf("unknow obj ref %+v", ref)
}
