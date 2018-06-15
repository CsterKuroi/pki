package accesscontrol

import (
	cryptRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	mathRand "math/rand"
	"time"
)

func init() {
	mathRand.Seed(time.Now().UnixNano())
}

type CertInfo struct {
	Country            []string
	Organization       []string
	OrganizationalUnit []string
	EmailAddress       []string
	Province           []string
	Locality           []string
	CommonName         string
	IsCA               bool
	DNSnames           []string
}

func GenerateCert(RootCa *x509.Certificate, RootPri *rsa.PrivateKey, info CertInfo) (*pem.Block, *pem.Block, error) {
	Cert := newCert(info)
	bits := 1024
	privateKey, err := rsa.GenerateKey(cryptRand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	priBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	var buf []byte
	if RootCa == nil || RootPri == nil { // CA 自签名 ROOT cert
		buf, err = x509.CreateCertificate(cryptRand.Reader, Cert, Cert, &privateKey.PublicKey, privateKey)
	} else {
		buf, err = x509.CreateCertificate(cryptRand.Reader, Cert, RootCa, &privateKey.PublicKey, RootPri)
	}
	if err != nil {
		return nil, nil, err
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: buf,
	}
	return certBlock, priBlock, nil
}

type crlError struct{}

func (this *crlError) Error() string { return "CRL: IN Revoked Certificate List" }

func VerifyCert(orgCertObj *x509.Certificate, opts x509.VerifyOptions, crl *pkix.CertificateList) (bool, error) {
	_, err := orgCertObj.Verify(opts)
	if err != nil {
		return false, err
	}
	if IsCertInCRL(orgCertObj, crl) {
		return false, &crlError{}
	}
	return true, nil
}

func newCert(info CertInfo) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(mathRand.Int63()),
		Subject: pkix.Name{
			Country:            info.Country,
			Organization:       info.Organization,
			OrganizationalUnit: info.OrganizationalUnit,
			Province:           info.Province,
			CommonName:         info.CommonName,
			Locality:           info.Locality,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		BasicConstraintsValid: true,
		IsCA:           info.IsCA,                                                                  //是否是根证书
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, //证书用途
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		EmailAddresses: info.EmailAddress,
		DNSNames:       info.DNSnames,
		//CRLDistributionPoints
	}
}
