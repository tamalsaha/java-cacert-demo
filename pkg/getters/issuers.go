package getters

import (
	"fmt"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/tamalsaha/java-cacert-demo/pkg/getters/lib"
	"github.com/tamalsaha/java-cacert-demo/pkg/getters/providers"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCAGetter(c client.Client, ref lib.ObjectRef, obj client.Object) (lib.CAGetter, error) {
	switch ref.GroupKind() {
	case schema.GroupKind{Kind: "Secret"}:
		return new(providers.CAGetterSecret), nil
	case schema.GroupKind{Group: certmanager.GroupName, Kind: "Issuer"},
		schema.GroupKind{Group: certmanager.GroupName, Kind: "ClusterIssuer"}:
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
