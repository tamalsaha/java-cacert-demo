package lib

import (
	"crypto/x509"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CAProvider interface {
	GetCAs(obj client.Object, key string) ([]*x509.Certificate, error)
}
