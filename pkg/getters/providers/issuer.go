package providers

import (
	"crypto/x509"
	"fmt"
	"github.com/tamalsaha/java-cacert-demo/pkg/getters/lib"
	"gomodules.xyz/cert"
	"kmodules.xyz/cert-manager-util/reader"
)

type CAGetterIssuer struct {
	r   reader.Reader
	key lib.ObjectKey
}

var _ lib.CAGetter = &CAGetterIssuer{}

func (c *CAGetterIssuer) Init() error {
	_, err := c.r.Issuers(c.key.Namespace).Get(c.key.Name)
	return err
}

func (c *CAGetterIssuer) GetCAs(key string) ([]*x509.Certificate, error) {
	secret, err := c.r.Issuers(c.key.Namespace).Get(c.key.Name)
	if err != nil {
		return nil, err
	}
	data, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("missing key %s in secret %s/%s", key, c.key.Namespace, c.key.Name)
	}
	caCerts, _, err := cert.ParseRootCAs(data)
	return caCerts, err
}
