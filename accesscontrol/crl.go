package accesscontrol

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

func NewCRL() (*pkix.CertificateList, error) {

	block, _ := pem.Decode([]byte(template))
	cert, err := x509.ParseCRL(block.Bytes)
	//TODO not use template and update obj
	if err != nil {
		return nil, err
	}
	fmt.Println(cert.TBSCertList.RevokedCertificates)
	fmt.Println(*cert)
	return cert, nil
}

func Append2CRL(cert pkix.RevokedCertificate, crl *pkix.CertificateList) {
	newlist := append(crl.TBSCertList.RevokedCertificates, cert)
	crl.TBSCertList.RevokedCertificates = newlist
}

func IsCertInCRL(cert *x509.Certificate, crl *pkix.CertificateList) bool {
	for _, v := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber == v.SerialNumber {
			return true
		}
	}
	return false
}