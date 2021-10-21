package lib

import "crypto/x509"

type CAGetter interface {
	Init() error
	GetCAs(key string) ([]*x509.Certificate, error)
}

type ObjectReference struct {
	APIGroup  string `json:"apiGroup"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Key       string `json:"key,omitempty"`
}

type ObjectKey struct {
	APIGroup  string `json:"apiGroup"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Key       string `json:"key,omitempty"`
}
