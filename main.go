package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"gomodules.xyz/cert"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	keystore "github.com/pavel-v-chernykh/keystore-go/v4"
)

const crt = `-----BEGIN CERTIFICATE-----
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

func main() {
	certs, err := cert.ParseRootCAs([]byte(crt))
	if err != nil {
		panic(err)
	}
	for _, c := range certs {
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
		if !c.IsCA {
			continue
		}
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
