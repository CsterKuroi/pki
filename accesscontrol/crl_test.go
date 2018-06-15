package accesscontrol

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"testing"
	"time"
)

func TestNewCRL(t *testing.T) {
	crl, err := NewCRL()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(crl)
}

func TestAppend2CRL(t *testing.T) {
	crl, err := NewCRL()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(crl)

	rootInfo := CertInfo{
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

	orgInfo := CertInfo{
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
	orgCert, _, err := GenerateCert(rootCertObj, rootPriObj, orgInfo)
	if err != nil {
		log.Fatal(err)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(pem.EncodeToMemory(rootCert))
	if !ok {
		log.Fatal("failed to parse root certificate")
	}
	orgCertObj, err := x509.ParseCertificate(orgCert.Bytes)
	if err != nil {
		log.Fatal("failed to parse org certificate: " + err.Error())
	}

	rCert := pkix.RevokedCertificate{
		SerialNumber:   orgCertObj.SerialNumber,
		RevocationTime: time.Now(),
	}
	Append2CRL(rCert, crl)
	fmt.Println(crl)
}

func TestIsCertInCRL(t *testing.T) {
	crl, err := NewCRL()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(crl)

	rootInfo := CertInfo{
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

	orgInfo := CertInfo{
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
	orgCert, _, err := GenerateCert(rootCertObj, rootPriObj, orgInfo)
	if err != nil {
		log.Fatal(err)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(pem.EncodeToMemory(rootCert))
	if !ok {
		log.Fatal("failed to parse root certificate")
	}
	orgCertObj, err := x509.ParseCertificate(orgCert.Bytes)
	if err != nil {
		log.Fatal("failed to parse org certificate: " + err.Error())
	}

	rCert := pkix.RevokedCertificate{
		SerialNumber:   orgCertObj.SerialNumber,
		RevocationTime: time.Now(),
	}
	Append2CRL(rCert, crl)
	fmt.Println(crl)

	valid := IsCertInCRL(orgCertObj, crl)
	fmt.Println(valid)
	valid = IsCertInCRL(rootCertObj, crl)
	fmt.Println(valid)
}
