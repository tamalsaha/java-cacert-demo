package providers

import (
	"crypto/x509"
	"fmt"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/tamalsaha/java-cacert-demo/pkg/getters/lib"
	"gomodules.xyz/cert"
	"kmodules.xyz/client-go/tools/configreader"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CAGetterIssuer struct {
	reader configreader.ConfigReader
	key    lib.ObjectRef
}

var _ lib.CAGetter = &CAGetterIssuer{}

func (c *CAGetterIssuer) Init() error {
	return nil
}

func (c *CAGetterIssuer) GetCAs(obj client.Object, key string) ([]*x509.Certificate, error) {
	issuer, ok := obj.(cmapi.GenericIssuer)
	if !ok {
		return nil, fmt.Errorf("%v %s/%s is not a GenericIssuer", obj.GetObjectKind().GroupVersionKind(), obj.GetNamespace(), obj.GetName())
	}
	if issuer.GetSpec().CA == nil {
		return nil, fmt.Errorf("%v %s/%s does not have a CA", issuer.GetObjectKind().GroupVersionKind(), issuer.GetNamespace(), issuer.GetName())
	}
	secret, err := c.reader.Secrets(issuer.GetNamespace()).Get(issuer.GetName())
	if err != nil {
		return nil, err
	}
	data, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("missing key %s in secret %s/%s", key, c.key.Namespace, c.key.Name)
	}
	caCerts, _, err := cert.ParseRootCAs(data)
	if err != nil {
		return nil, err
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("%v %s/%s signing certificate is not a CA", issuer.GetObjectKind().GroupVersionKind(), issuer.GetNamespace(), issuer.GetName())
	}
	return caCerts, err
}
