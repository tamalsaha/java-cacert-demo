/*
Copyright AppsCode Inc. and Contributors

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

package configreader

import (
	"sync"

	cs "kubeops.dev/csi-driver-cacerts/client/clientset/versioned"
	listers "kubeops.dev/csi-driver-cacerts/client/listers/cacerts/v1alpha1"
)

type directImpl struct {
	dc cs.Interface

	lock                  sync.RWMutex
	caProviderClassLister listers.CAProviderClassNamespaceLister
}

var _ Reader = &directImpl{}

func (i *directImpl) CAProviderClasses(namespace string) listers.CAProviderClassNamespaceLister {
	i.lock.RLock()
	defer i.lock.RUnlock()
	if i.caProviderClassLister != nil {
		return i.caProviderClassLister
	}

	i.caProviderClassLister = &caProviderClassNamespaceLister{dc: i.dc, namespace: namespace}
	return i.caProviderClassLister
}
