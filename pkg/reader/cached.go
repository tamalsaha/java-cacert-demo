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
	"fmt"
	"reflect"
	"sync"

	api "kubeops.dev/csi-driver-cacerts/apis/cacerts/v1alpha1"
	informers "kubeops.dev/csi-driver-cacerts/client/informers/externalversions"
	listers "kubeops.dev/csi-driver-cacerts/client/listers/cacerts/v1alpha1"
)

type cachedImpl struct {
	factory informers.SharedInformerFactory
	stopCh  <-chan struct{}

	lock                  sync.RWMutex
	caProviderClassLister listers.CAProviderClassLister
}

var _ Reader = &cachedImpl{}

func (i *cachedImpl) CAProviderClasses(namespace string) listers.CAProviderClassNamespaceLister {
	i.lock.RLock()
	if i.caProviderClassLister != nil {
		i.lock.RUnlock()
		return i.caProviderClassLister.CAProviderClasses(namespace)
	}
	i.lock.RUnlock()

	createLister := func() listers.CAProviderClassLister {
		i.lock.Lock()
		defer i.lock.Unlock()
		if i.caProviderClassLister != nil {
			return i.caProviderClassLister
		}

		informerType := reflect.TypeOf(&api.CAProviderClass{})
		informerDep, _ := i.factory.ForResource(api.SchemeGroupVersion.WithResource("secrets"))
		i.factory.Start(i.stopCh)
		if synced := i.factory.WaitForCacheSync(i.stopCh); !synced[informerType] {
			panic(fmt.Sprintf("informer for %s hasn't synced", informerType))
		}
		i.caProviderClassLister = listers.NewCAProviderClassLister(informerDep.Informer().GetIndexer())
		return i.caProviderClassLister
	}
	return createLister().CAProviderClasses(namespace)
}
