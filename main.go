package main

import (
	"fmt"
	keystore "github.com/pavel-v-chernykh/keystore-go/v4"
	"os"
)

func main() {
	filename := "/home/tamal/go/src/kubeops.dev/csi-driver-ca-certificates/examples/cacerts/etc/ssl/certs/java/cacerts"
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	ks := keystore.New()
	if err := ks.Load(f, []byte("changeit")); err != nil {
		panic(err)
	}
	for _, alias := range ks.Aliases() {
		if crt, err := ks.GetTrustedCertificateEntry(alias); err != nil {
			panic(err)
		} else {
			fmt.Printf("%s: %s %s\n", alias, crt.Certificate.Type, crt.CreationTime)
		}
	}
}
