package accesscontrol

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

func NewCRL() (*pkix.CertificateList, error) {

	block, _ := pem.Decode([]byte(template))
	crl, err := x509.ParseCRL(block.Bytes)
	//TODO not use template and update obj
	if err != nil {
		return nil, err
	}
	return crl, nil
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
