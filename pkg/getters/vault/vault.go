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
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/tamalsaha/java-cacert-demo/pkg/getters/lib"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Vault struct {
	reader client.Reader
	opts   IssuerOptions

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string
}

func NewVault(c client.Reader, opts IssuerOptions) (lib.CAGetter, error) {
	return &Vault{
		reader: c,
		opts:   opts,
	}, nil
}

//// Register this Issuer with the issuer factory
//func init() {
//	issuer.RegisterIssuer(apiutil.IssuerVault, NewVault)
//}

type IssuerOptions struct {
	// ClusterResourceNamespace is the namespace to store resources created by
	// non-namespaced resources (e.g. ClusterIssuer) in.
	ClusterResourceNamespace string

	// ClusterIssuerAmbientCredentials controls whether a cluster issuer should
	// pick up ambient credentials, such as those from metadata services, to
	// construct clients.
	ClusterIssuerAmbientCredentials bool

	// IssuerAmbientCredentials controls whether an issuer should pick up ambient
	// credentials, such as those from metadata services, to construct clients.
	IssuerAmbientCredentials bool
}

func (o IssuerOptions) ResourceNamespace(iss cmapi.GenericIssuer) string {
	ns := iss.GetObjectMeta().Namespace
	if ns == "" {
		ns = o.ClusterResourceNamespace
	}
	return ns
}
