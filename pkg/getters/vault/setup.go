/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"crypto/x509"
	"fmt"
	"gomodules.xyz/cert"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	vaultinternal "github.com/tamalsaha/java-cacert-demo/pkg/internal/vault"
)

const (
	successVaultVerified = "VaultVerified"
	messageVaultVerified = "Vault verified"

	errorVault = "VaultError"

	messageVaultClientInitFailed         = "Failed to initialize Vault client: "
	messageVaultStatusVerificationFailed = "Vault is not initialized or is sealed"
	messageVaultConfigRequired           = "Vault config cannot be empty"
	messageServerAndPathRequired         = "Vault server and path are required fields"
	messageAuthFieldsRequired            = "Vault tokenSecretRef, appRole, or kubernetes is required"
	messageMultipleAuthFieldsSet         = "Multiple auth methods cannot be set on the same Vault issuer"

	messageKubeAuthFieldsRequired    = "Vault Kubernetes auth requires both role and secretRef.name"
	messageTokenAuthNameRequired     = "Vault Token auth requires tokenSecretRef.name"
	messageAppRoleAuthFieldsRequired = "Vault AppRole auth requires both roleId and tokenSecretRef.name"
)

func (v *Vault) GetCAs(obj client.Object, _ string) ([]*x509.Certificate, error) {
	issuer, ok := obj.(cmapi.GenericIssuer)
	if !ok {
		return nil, fmt.Errorf("%v %s/%s is not a GenericIssuer", obj.GetObjectKind().GroupVersionKind(), obj.GetNamespace(), obj.GetName())
	}

	if issuer.GetSpec().Vault == nil {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageVaultConfigRequired)
	}

	// check if Vault server info is specified.
	if issuer.GetSpec().Vault.Server == "" ||
		issuer.GetSpec().Vault.Path == "" {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageServerAndPathRequired)
	}

	tokenAuth := issuer.GetSpec().Vault.Auth.TokenSecretRef
	appRoleAuth := issuer.GetSpec().Vault.Auth.AppRole
	kubeAuth := issuer.GetSpec().Vault.Auth.Kubernetes

	// check if at least one auth method is specified.
	if tokenAuth == nil && appRoleAuth == nil && kubeAuth == nil {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageAuthFieldsRequired)
	}

	// check only one auth method set
	if (tokenAuth != nil && appRoleAuth != nil) ||
		(tokenAuth != nil && kubeAuth != nil) ||
		(appRoleAuth != nil && kubeAuth != nil) {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageMultipleAuthFieldsSet)
	}

	// check if all mandatory Vault Token fields are set.
	if tokenAuth != nil && len(tokenAuth.Name) == 0 {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageTokenAuthNameRequired)
	}

	// check if all mandatory Vault appRole fields are set.
	if appRoleAuth != nil && (len(appRoleAuth.RoleId) == 0 || len(appRoleAuth.SecretRef.Name) == 0) {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageAppRoleAuthFieldsRequired)
	}

	// check if all mandatory Vault Kubernetes fields are set.
	if kubeAuth != nil && (len(kubeAuth.SecretRef.Name) == 0 || len(kubeAuth.Role) == 0) {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageKubeAuthFieldsRequired)
	}

	vc, err := vaultinternal.New(v.resourceNamespace, v.reader, issuer)
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, s)
	}

	if err := vc.IsVaultInitializedAndUnsealed(); err != nil {
		return nil, fmt.Errorf("%s: %s: error: %s", issuer.GetObjectMeta().Name, messageVaultStatusVerificationFailed, err.Error())
	}

	caPEM, err := vc.CA()
	if err != nil {
		return nil, err
	}
	caCerts, _, err := cert.ParseRootCAs(caPEM)
	if err != nil {
		return nil, err
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("%v %s/%s signing certificate is not a CA", issuer.GetObjectKind().GroupVersionKind(), issuer.GetNamespace(), issuer.GetName())
	}
	return caCerts, err
}
