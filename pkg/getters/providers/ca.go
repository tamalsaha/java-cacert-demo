package providers

import (
	"context"
	"crypto/x509"
	"fmt"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/tamalsaha/java-cacert-demo/pkg/getters/lib"
	"gomodules.xyz/cert"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CAGetterIssuer struct {
	Reader client.Reader
}

var _ lib.CAGetter = &CAGetterIssuer{}

func (c *CAGetterIssuer) GetCAs(obj client.Object, key string) ([]*x509.Certificate, error) {
	issuer, ok := obj.(cmapi.GenericIssuer)
	if !ok {
		return nil, fmt.Errorf("%v %s/%s is not a GenericIssuer", obj.GetObjectKind().GroupVersionKind(), obj.GetNamespace(), obj.GetName())
	}
	if issuer.GetSpec().CA == nil {
		return nil, fmt.Errorf("%v %s/%s does not have a CA", issuer.GetObjectKind().GroupVersionKind(), issuer.GetNamespace(), issuer.GetName())
	}

	var secret corev1.Secret
	secretRef := client.ObjectKey{
		Namespace: issuer.GetNamespace(),
		Name:      issuer.GetSpec().CA.SecretName,
	}
	err := c.Reader.Get(context.TODO(), secretRef, &secret)
	if err != nil {
		return nil, err
	}
	data, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("missing key %s in secret %s", key, secretRef)
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
