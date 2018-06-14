package accesscontrol

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	rd "math/rand"
	"time"
)

func init() {
	rd.Seed(time.Now().UnixNano())
}

type CertInformation struct {
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

func GenerateCert(RootCa *x509.Certificate, RootPri *rsa.PrivateKey, info CertInformation) (*pem.Block, *pem.Block, error) {
	Cert := newCertificate(info)
	bits := 1024
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	priBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	var buf []byte
	if RootCa == nil || RootPri == nil { // CA 自签名 ROOT cert
		buf, err = x509.CreateCertificate(rand.Reader, Cert, Cert, &privateKey.PublicKey, privateKey)
	} else {
		buf, err = x509.CreateCertificate(rand.Reader, Cert, RootCa, &privateKey.PublicKey, RootPri)
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

func VerifyCert(orgCertObj *x509.Certificate, opts x509.VerifyOptions) (bool, error) {
	_, err := orgCertObj.Verify(opts)
	if err != nil {
		return false, err
	}
	//TODO 废除列表
	//if orgCertObj in crl {return false,crlerror}
	return true, nil
}

func newCertificate(info CertInformation) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(rd.Int63()),
		Subject: pkix.Name{
			Country:            info.Country,
			Organization:       info.Organization,
			OrganizationalUnit: info.OrganizationalUnit,
			Province:           info.Province,
			CommonName:         info.CommonName,
			Locality:           info.Locality,
		},
		NotBefore:             time.Now(),                   //证书的开始时间
		NotAfter:              time.Now().AddDate(20, 0, 0), //证书的结束时间
		BasicConstraintsValid: true,                         //基本的有效性约束
		IsCA:           info.IsCA,                                                                  //是否是根证书
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, //证书用途
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		EmailAddresses: info.EmailAddress,
		DNSNames:       info.DNSnames,
	}
}
