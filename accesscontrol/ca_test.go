package accesscontrol

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"testing"
)

func TestGenerateCert(t *testing.T) {
	rootInfo := CertInformation{
		Country:            []string{"CN"},
		Organization:       []string{"jihao-CA"},
		IsCA:               true,
		OrganizationalUnit: []string{"buaa"},
		EmailAddress:       []string{"jihao@buaa.edu.cn"},
		Locality:           []string{"Haidian"},
		Province:           []string{"Beijing"},
		CommonName:         "www.ca.com",
		DNSnames:           []string{"www.ca.com"},
	}
	cert, pri, err := GenerateCert(nil, nil, rootInfo)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cert)
	fmt.Println(pri)
}

func TestVerifyCert(t *testing.T) {
	rootInfo := CertInformation{
		Country:            []string{"CN"},
		Organization:       []string{"jihao-CA"},
		IsCA:               true,
		OrganizationalUnit: []string{"buaa"},
		EmailAddress:       []string{"jihao@buaa.edu.cn"},
		Locality:           []string{"Haidian"},
		Province:           []string{"Beijing"},
		CommonName:         "www.ca.com",
		DNSnames:           []string{"www.ca.com"},
	}
	rootCert, rootPri, err := GenerateCert(nil, nil, rootInfo)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rootCert)
	fmt.Println(rootPri)

	orgInfo := CertInformation{
		Country:            []string{"UK"},
		Organization:       []string{"overwatch"},
		IsCA:               true,
		OrganizationalUnit: []string{"darkwatch"},
		EmailAddress:       []string{"tracer@overwatch.com"},
		Locality:           []string{"London"},
		Province:           []string{"England"},
		CommonName:         "www.overwatch.com",
		DNSnames:           []string{"www.overwatch.com"},
	}
	rootCertObj, err := x509.ParseCertificate(rootCert.Bytes)
	rootPriObj, err := x509.ParsePKCS1PrivateKey(rootPri.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	orgCert, orgPri, err := GenerateCert(rootCertObj, rootPriObj, orgInfo)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(orgCert)
	fmt.Println(orgPri)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(pem.EncodeToMemory(rootCert))
	if !ok {
		log.Fatal("failed to parse root certificate")
	}
	orgCertObj, err := x509.ParseCertificate(orgCert.Bytes)
	if err != nil {
		log.Fatal("failed to parse org certificate: " + err.Error())
	}
	opts := x509.VerifyOptions{
		DNSName: "www.overwatch.com",
		Roots:   roots,
	}
	valid, err := VerifyCert(orgCertObj, opts)
	fmt.Println(valid, err)
	opts2 := x509.VerifyOptions{
		DNSName: "www.overwatch.com",
	}
	valid, err = VerifyCert(orgCertObj, opts2)
	fmt.Println(valid, err)
}
