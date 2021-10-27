package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/runtime"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tamalsaha/java-cacert-demo/pkg/providers"

	cmv1_api "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	cmv1_cs "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	keystore "github.com/pavel-v-chernykh/keystore-go/v4"
	"github.com/tamalsaha/java-cacert-demo/pkg/providers/lib"
	"github.com/zeebo/xxh3"
	atomic_writer "gomodules.xyz/atomic-writer"
	"gomodules.xyz/cert"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog/v2/klogr"
	cacerts_api "kubeops.dev/csi-driver-cacerts/apis/cacerts/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

const selfsigned_crt = `-----BEGIN CERTIFICATE-----
MIIC3jCCAcagAwIBAgIRAJSoxqtKjIrJHtl3pZTNNwUwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMTEwMTcwNjEzMjFaFw0yMjAxMTUwNjEzMjFaMAAwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDP2RLFpM8/fMGBHVX6DTEyRVFuYMH+2A8UFJoD
tPCp+SePlltt3p98saAaZ/NJGWdtivDLIzK7QanELBN0rg9cRHUEmk8Umtn2U2FL
5CizwnUBWzpctop0XXlo+B+2BGKAw8//vluv+ZIXPdjjmQGr0CQa8TRp4dWN5R2/
TgA6n0XvM/pT3KljSjpPsJoVTD5FLmjed+YBFRUge3v00x+ZvG3Mxri/MDdLWX2I
n2XJ8kkyy98XdSf7MjGVzMGbbSQaU9ZegSBZCQN23SnCsxAC2aI7ZWLO1YzjAPMt
fUypvSfCBOkA9mYVEK5j21W84ot8OTSlUBhYA6yaeI0FfYelAgMBAAGjUzBRMA4G
A1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMDEGA1UdEQEB/wQnMCWCDSouZXhh
bXBsZS5jb22CC2V4YW1wbGUuY29tggdmb28uY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQCmOzSNnKeMvBj5X7SBCAFOwg0YROPkbWnLLGjMMR1EvvRjHqB7cAL8Kh+E2ml8
NtYKzSqw15PGSBgZM1rWHDuZDuaAYqGIgsSJRZhsNAMlcyfOeI3UCPjI1UIqwBI2
4WxfBkzZxnspU0o/09e9c76NICiXXeSN/1Wuq40z9QzID6qD+kX3qT2kuJuhfvxH
rVsW2gUshCyiEQRyT4k1XkEB7rwt/w12PSJjFXP5uea9PbYdkFMORS8ctDbLH66M
kFwOpGutk2d34+mk4PwuAJ0wWwBRyLL+jJyUAQ0cpgHzadLieFN7g5hcIjCoT2Ya
CZVBw5BuXV6QTSfYfm/BgsiQ
-----END CERTIFICATE-----`

const selfsigned_ca_crt = `-----BEGIN CERTIFICATE-----
MIIDADCCAeigAwIBAgIRAK+AG4IIvfCKiGPuuHPVsiwwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMTEwMTcwNzMzMDFaFw0yMjAxMTUwNzMzMDFaMAAwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDP2RLFpM8/fMGBHVX6DTEyRVFuYMH+2A8UFJoD
tPCp+SePlltt3p98saAaZ/NJGWdtivDLIzK7QanELBN0rg9cRHUEmk8Umtn2U2FL
5CizwnUBWzpctop0XXlo+B+2BGKAw8//vluv+ZIXPdjjmQGr0CQa8TRp4dWN5R2/
TgA6n0XvM/pT3KljSjpPsJoVTD5FLmjed+YBFRUge3v00x+ZvG3Mxri/MDdLWX2I
n2XJ8kkyy98XdSf7MjGVzMGbbSQaU9ZegSBZCQN23SnCsxAC2aI7ZWLO1YzjAPMt
fUypvSfCBOkA9mYVEK5j21W84ot8OTSlUBhYA6yaeI0FfYelAgMBAAGjdTBzMA4G
A1UdDwEB/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ/WvJ4WCRU
+5LwiWBih0zHuG1UETAxBgNVHREBAf8EJzAlgg0qLmV4YW1wbGUuY29tggtleGFt
cGxlLmNvbYIHZm9vLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAUzyhXvwlZBwzrWvP
xBOT6BFANL/tAr/58vg8ah/hn5b2TVsmQNlYx3d9jye4n1gEUmxP/pjYJedvUzfn
ske7WjfZfzgw5inkPznHqjBOp6wHNh7NFpEy3gkCFSQk6XyTbxFK6lkPMBcMvlPQ
xKkHFaToqPhkUmK23+1U/ODB6EdjTqSbzmUVyOOPOZfI7N7ZtVIIe1JVT6xemgaC
0tad59ve/p3PbMGyI6rYxnTwiopv2SoW4i3qExE+nYoUIcM6R4uVwvRo18AwAFlz
qRm+WKJBnzCUNroHk5H2wn20rez4iJ5JZnnwWS+B9Sn8T63HBAeN7VBtw8rof+9h
jwcYNQ==
-----END CERTIFICATE-----`

const ca_crt = `-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIUfusT4Oj1uXMuUJ05AZG1gDz5px0wDQYJKoZIhvcNAQEL
BQAwITEOMAwGA1UEAwwFbW9uZ28xDzANBgNVBAoMBmt1YmVkYjAeFw0yMDA4MDcw
NDMyMzRaFw0yMTA4MDcwNDMyMzRaMCExDjAMBgNVBAMMBW1vbmdvMQ8wDQYDVQQK
DAZrdWJlZGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwVVSXBRME
rfXVu23cMqRoPr3JFGlIGxqgPzN+wlteOlTQptVkbt+qv44Lrk1n45AFvNe+dEpI
XLvt6B9dkJhDz34Cj4MwWeOekSJ2jmWxMSNArD4MoCCIyIq++4xYGBsf9Xx2Frtd
fvg9qp4QcLEmzqWh/w3TikNY2QZWe726BlatdugP7xxrJXG8E5Hi6xK9ukbsG+xd
DE0snXr++dp+qBaumo0hjGuS6QlErqAnm4LwPXxiZSRmGVGgtj0NmZD+jkI48UI8
Lfl9GCfbczcD3+ludlpNksnEQGpxABfhtYcw5357p+KJw5fVQjRdRzT5pZ/vtU3g
B+g83sWEBSVjAgMBAAGjUzBRMB0GA1UdDgQWBBSQjI2uKX0jicKnVo0EbQd8EFYI
NjAfBgNVHSMEGDAWgBSQjI2uKX0jicKnVo0EbQd8EFYINjAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCCoY503sixXQ7246jLvU246wcc64ulTQGb
4oAdDOjK9b55sY/ZU+aBZXNwK50UNU1Nkp6z6KjBZcTWUDwwOad2/RSSSCitL+Tv
NBr+fH0y/qoQvLUxEJq/rMd/6s5r4bjcRO6m+hekr/L7KSISyrGspUVDHxdHlWOm
RR2azvXWAqNYGorm9fpeRjnCrIvMTRiR7yw0l/3HHRYsysOTkLd7CdIwIS75dk6P
TISRT+2N9H0O9wJZtbpgXwy3mLR/yXhd0y6XHI9f4NXTxnG6K480eaJf5ng8wktQ
HTUsNM2cNy69KwgxR0KA4H6mFEoPWlk8ojFTSxCIieWzsv95Pdm6
-----END CERTIFICATE-----
`

var caCahce = map[lib.ObjectRef][]*x509.Certificate{}
var caGetterFactory = map[schema.GroupKind]lib.CAProvider{}

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func main() {
	if err := main__(); err != nil {
		panic(err)
	}
}

func main__() error {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = cmscheme.AddToScheme(scheme)
	_ = cacerts_api.AddToScheme(scheme)

	ctrl.SetLogger(klogr.New())
	cfg := ctrl.GetConfigOrDie()

	mapper, err := apiutil.NewDynamicRESTMapper(cfg)
	if err != nil {
		return err
	}

	c, err := client.New(cfg, client.Options{
		Scheme: scheme,
		Mapper: mapper,
		Opts: client.WarningHandlerOptions{
			SuppressWarnings:   false,
			AllowDuplicateLogs: false,
		},
	})
	if err != nil {
		return err
	}

	var pc cacerts_api.CAProviderClass
	err = c.Get(context.TODO(), client.ObjectKey{
		Namespace: "demo",
		Name:      "ca-provider",
	}, &pc)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(pc, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))

	certs := map[uint64]*x509.Certificate{}
	// https://stackoverflow.com/a/9104143
	for _, typedRef := range pc.Spec.Refs {
		ref := lib.RefFrom(pc, typedRef)
		obj, err := lib.GetObj(c, mapper, ref)
		if err != nil {
			return err
		}

		getter, err := providers.NewCAProvider(c, ref, obj)
		if err != nil {
			return err
		}
		cas, err := getter.GetCAs(obj, ref.Key)
		if err != nil {
			return err
		}
		for _, ca := range cas {
			certs[xxh3.Hash(ca.Raw)] = ca
		}
	}

	/*
		/home/tamal/go/src/github.com/tamalsaha/java-cacert-demo/hack/examples/cacerts/etc/ssl/certs/ca-certificates.crt
		/home/tamal/go/src/github.com/tamalsaha/java-cacert-demo/hack/examples/cacerts/etc/ssl/certs/java/cacerts
	*/

	certIds := make([]uint64, 0, len(certs))
	for id := range certs {
		certIds = append(certIds, id)
	}
	sort.Slice(certIds, func(i, j int) bool {
		return certIds[i] < certIds[j]
	})

	filename := "/home/tamal/go/src/github.com/tamalsaha/java-cacert-demo/hack/examples/cacerts/etc/ssl/certs/java/cacerts"
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	ks := keystore.New()
	if err := ks.Load(f, []byte("changeit")); err != nil {
		return err
	}
	for _, alias := range ks.Aliases() {
		if crt, err := ks.GetTrustedCertificateEntry(alias); err != nil {
			return err
		} else {
			fmt.Printf("%s: %s %s\n", alias, crt.Certificate.Type, crt.CreationTime)
		}
	}
	for _, certId := range certIds {
		ca := certs[certId]
		err := ks.SetTrustedCertificateEntry(fmt.Sprintf("%d", certId), keystore.TrustedCertificateEntry{
			CreationTime: ca.NotBefore,
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: ca.Raw,
			},
		})
		if err != nil {
			return err
		}
	}

	var javaBuf bytes.Buffer
	if err := ks.Store(&javaBuf, []byte("changeit")); err != nil {
		return err
	}

	var caBuf bytes.Buffer
	caData, err := ioutil.ReadFile("/home/tamal/go/src/github.com/tamalsaha/java-cacert-demo/hack/examples/cacerts/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		return err
	}
	caBuf.Write(caData)
	//f2, err := os.Open("/home/tamal/go/src/github.com/tamalsaha/java-cacert-demo/hack/examples/cacerts/etc/ssl/certs/ca-certificates.crt")
	//if err != nil {
	//	return err
	//}
	//defer f2.Close()
	//if _, err := io.Copy(&caBuf, f); err != nil {
	//	return err
	//}

	for _, certId := range certIds {
		ca := certs[certId]
		block := pem.Block{
			Type:  cert.CertificateBlockType,
			Bytes: ca.Raw,
		}
		err := pem.Encode(&caBuf, &block)
		if err != nil {
			return err
		}
	}

	writerContext := "ca-provider-csi-driver-ctx"
	targetDir := "/home/tamal/go/src/github.com/tamalsaha/java-cacert-demo/output"
	err = os.MkdirAll(targetDir, 0755)
	if err != nil {
		return
	}
	certWriter, err := atomic_writer.NewAtomicWriter(targetDir, writerContext)
	if err != nil {
		return
	}
	_, err = certWriter.Write(map[string]atomic_writer.FileProjection{
		"ca-certificates.crt": {Data: caBuf.Bytes(), Mode: 0400},
		"java/cacerts":        {Data: javaBuf.Bytes(), Mode: 0400},
	})
	if err != nil {
		return
	}
}

func main22() {
	caCerts, certs, err := cert.ParseRootCAs([]byte(selfsigned_ca_crt))
	if err != nil {
		return err
	}
	for _, c := range caCerts {
		fmt.Println("ca", c.SerialNumber.String(), c.Subject.String())
	}
	for _, c := range certs {
		fmt.Println("non-ca", c.SerialNumber.String(), c.Subject.String()) // Subject is ""
	}
}

func main_selfsigned_crt() {
	caCerts, certs, err := cert.ParseRootCAs([]byte(selfsigned_crt))
	if err != nil {
		return err
	}
	for _, c := range caCerts {
		fmt.Println("ca", c.SerialNumber.String(), c.Subject.String())
	}
	for _, c := range certs {
		fmt.Println("non-ca", c.SerialNumber.String(), c.Subject.String()) // Subject is ""
	}
}

func main00() {
	masterURL := ""
	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
	kubeconfigPath = "/home/tamal/Downloads/mysql-test-kubeconfig.yaml"

	config, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfigPath)
	if err != nil {
		log.Fatalf("Could not get Kubernetes config: %s", err)
	}

	kc := kubernetes.NewForConfigOrDie(config)
	cmc := cmv1_cs.NewForConfigOrDie(config)
	var issuer *cmv1_api.Issuer
	var caissuer *cmv1_api.ClusterIssuer
	fmt.Println(kc, cmc, issuer, caissuer)

	caCerts, _, err := cert.ParseRootCAs([]byte(ca_crt))
	if err != nil {
		return err
	}
	for _, c := range caCerts {
		fmt.Println(c.SerialNumber.String(), c.Subject.String())
	}
}

// Detect Self Signed cert
// https://security.stackexchange.com/a/162263
func ParseRootCAs(rest []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	var block *pem.Block
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			// panic("failed to parse certificate PEM")
			break
		}
		if block.Type != "CERTIFICATE" {
			// panic("failed to parse certificate PEM")
			continue
		}

		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		//if !c.IsCA {
		//	continue
		//}
		if !reflect.DeepEqual(c.Issuer, c.Subject) {
			// fmt.Println("Subject and Issuer does not match")
			continue
		}
		if len(c.AuthorityKeyId) == 0 || bytes.Equal(c.SubjectKeyId, c.AuthorityKeyId) {
			certs = append(certs, c)
		}
	}
	return certs, nil
}

func conv(r string) string {
	r = strings.Replace(r, `^([^\ :]*)\ `, `^`, 1)
	r = strings.Replace(r, `\1\ `, ``, 1)
	re := regexp.MustCompile(`[0-9]+`)
	r = re.ReplaceAllStringFunc(r, func(s string) string {
		i, _ := strconv.Atoi(s)
		return strconv.Itoa(i - 1)
	})
	return r
}

func main3() {
	fmt.Println(conv(`^([^\ :]*)\ \/domains\/espress\/?(.*$) \1\ /\2`))
}

func main34() {
	filename := "/home/tamal/go/src/github.com/tamalsaha/java-cacert-demo/hack/examples/cacerts/etc/ssl/certs/java/cacerts"
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	ks := keystore.New()
	if err := ks.Load(f, []byte("changeit")); err != nil {
		return err
	}
	for _, alias := range ks.Aliases() {
		if crt, err := ks.GetTrustedCertificateEntry(alias); err != nil {
			return err
		} else {
			fmt.Printf("%s: %s %s\n", alias, crt.Certificate.Type, crt.CreationTime)
		}
	}

}
