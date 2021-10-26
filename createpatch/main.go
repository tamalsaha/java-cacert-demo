package main

import (
	"fmt"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	opts := []client.PatchOption{
		client.DryRunAll,
		client.FieldOwner("kubedb"),
		client.ForceOwnership,
	}
	createOpts := make([]client.CreateOption, 0, len(opts))
	for _, opt := range opts {
		if o, ok := opt.(client.CreateOption); ok {
			createOpts = append(createOpts, o)
		}
	}

	fmt.Println(len(createOpts))
}
