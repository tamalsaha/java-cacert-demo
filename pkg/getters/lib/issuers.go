package lib

import (
	"fmt"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

const (
	// IssuerACME is the name of the ACME issuer
	IssuerACME string = "acme"
	// IssuerCA is the name of the simple issuer
	IssuerCA string = "ca"
	// IssuerVault is the name of the Vault issuer
	IssuerVault string = "vault"
	// IssuerSelfSigned is a self signing issuer
	IssuerSelfSigned string = "selfsigned"
	// IssuerVenafi uses Venafi Trust Protection Platform and Venafi Cloud
	IssuerVenafi string = "venafi"
)

// NameForIssuer determines the name of the Issuer implementation given an
// Issuer resource.
func NameForIssuer(i cmapi.GenericIssuer) (string, error) {
	switch {
	case i.GetSpec().ACME != nil:
		return IssuerACME, nil
	case i.GetSpec().CA != nil:
		return IssuerCA, nil
	case i.GetSpec().Vault != nil:
		return IssuerVault, nil
	case i.GetSpec().SelfSigned != nil:
		return IssuerSelfSigned, nil
	case i.GetSpec().Venafi != nil:
		return IssuerVenafi, nil
	}
	return "", fmt.Errorf("no issuer specified for Issuer '%s/%s'", i.GetObjectMeta().Namespace, i.GetObjectMeta().Name)
}