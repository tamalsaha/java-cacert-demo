package providers

import (
	"crypto/x509"
	"fmt"
	"github.com/tamalsaha/java-cacert-demo/pkg/getters/lib"
	"gomodules.xyz/cert"
	corev1 "k8s.io/api/core/v1"
	"kmodules.xyz/client-go/tools/configreader"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CAGetterSecret struct {
	reader configreader.ConfigReader
	key    lib.ObjectRef
}

var _ lib.CAGetter = &CAGetterSecret{}

func (c *CAGetterSecret) Init() error {
	_, err := c.reader.Secrets(c.key.Namespace).Get(c.key.Name)
	return err
}

func (c *CAGetterSecret) GetCAs(obj client.Object, key string) ([]*x509.Certificate, error) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil, fmt.Errorf("%v %s/%s is not a Secret", obj.GetObjectKind().GroupVersionKind(), obj.GetNamespace(), obj.GetName())
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
		return nil, fmt.Errorf("%v %s/%s signing certificate is not a CA", secret.GetObjectKind().GroupVersionKind(), secret.GetNamespace(), secret.GetName())
	}
	return caCerts, err
}
