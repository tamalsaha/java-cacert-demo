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
	"time"

	informers "kubeops.dev/csi-driver-cacerts/client/informers/externalversions"
	cs "kubeops.dev/csi-driver-cacerts/client/clientset/versioned"
	listers "kubeops.dev/csi-driver-cacerts/client/listers/cacerts/v1alpha1"
)

type Reader interface {
	CAProviderClasses(namespace string) listers.CAProviderClassNamespaceLister
}

func New(dc cs.Interface) Reader {
	return &directImpl{
		dc: dc,
	}
}

func NewCached(dc cs.Interface, defaultResync time.Duration, stopCh <-chan struct{}) Reader {
	return &cachedImpl{
		factory: informers.NewSharedInformerFactory(dc, defaultResync),
		stopCh:  stopCh,
	}
}

func NewCachedWithOptions(dc cs.Interface, defaultResync time.Duration, stopCh <-chan struct{}, options ...informers.SharedInformerOption) Reader {
	return &cachedImpl{
		factory: informers.NewSharedInformerFactoryWithOptions(dc, defaultResync, options...),
		stopCh:  stopCh,
	}
}

func NewSharedCached(factory informers.SharedInformerFactory, stopCh <-chan struct{}) Reader {
	return &cachedImpl{
		factory: factory,
		stopCh:  stopCh,
	}
}
