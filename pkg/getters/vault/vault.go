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
	"kmodules.xyz/client-go/tools/configreader"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

type Vault struct {
	*controller.Context
	issuer v1.GenericIssuer

	secretsReader configreader.ConfigReader

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string
}

func NewVault(ctx *controller.Context, issuer v1.GenericIssuer) (issuer.Interface, error) {
	return &Vault{
		Context:           ctx,
		issuer:            issuer,
		secretsReader:     configreader.New(ctx.Client),
		resourceNamespace: ctx.IssuerOptions.ResourceNamespace(issuer),
	}, nil
}

// Register this Issuer with the issuer factory
func init() {
	issuer.RegisterIssuer(apiutil.IssuerVault, NewVault)
}
