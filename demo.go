package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/CsterKuroi/pki/accesscontrol"
	"github.com/CsterKuroi/pki/common/nacl/sign"
	"github.com/CsterKuroi/pki/common/rsa"

	"crypto/x509/pkix"
	"github.com/btcsuite/btcutil/base58"
	"time"
)

const start = `
 ____    _____      _      ____    _____ 
/ ___|  |_   _|    / \    |  _ \  |_   _|
\___ \    | |     / _ \   | |_) |   | |  
 ___) |   | |    / ___ \  |  _ <    | |  
|____/    |_|   /_/   \_\ |_| \_\   |_|  
`
const end = `
 _____   _   _   ____   
| ____| | \ | | |  _ \  
|  _|   |  \| | | | | | 
| |___  | |\  | | |_| | 
|_____| |_| \_| |____/  
`

var rsaPrivate, rsaPublic, ed25519Private, ed25519Public, rootCert, rootPri, crl *pem.Block

func file2Pem(name string) *pem.Block {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(b)
	return block
}

func init() {
	rsaPrivate = file2Pem("./release/rsa_private.pem")
	rsaPublic = file2Pem("./release/rsa_public.pem")

	ed25519Private = file2Pem("./release/ed25519_private.pem")
	ed25519Public = file2Pem("./release/ed25519_public.pem")

	rootCert = file2Pem("./release/ca_root_crt.pem")
	rootPri = file2Pem("./release/ca_root_private.pem")

	crl = file2Pem("./release/ca_crl.pem")
}

func rsaDemo() {
	//rsa[gen,sign,verify,encrypt,decrypt]
	fmt.Println("===================== RSA DEMO(encrypt,decrypt) =====================")
	fakePri, fakePub := rsa.GenerateKeyPair()
	msg := []byte("The State Council decided last Wednesday")
	fmt.Println("origin msg  :", string(msg))
	cipher, err := rsa.Encrypt(msg, rsaPublic)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("encrypt  >> :", cipher)
	fmt.Println("b58 cipher  :", base58.Encode(cipher))
	plain, err := rsa.Decrypt(cipher, rsaPrivate)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypt  >> :", string(plain))
	plain, err = rsa.Decrypt(cipher, fakePri)
	fmt.Println("*decrypt*>> :", string(plain), err)

	fmt.Println("===================== RSA DEMO(sign,veryfy) =====================")
	signature, err := rsa.Sign(msg, rsaPrivate)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sign       >> :", signature)
	fmt.Println("b58 signature :", base58.Encode(signature))
	valid, _ := rsa.Verify(msg, signature, rsaPublic)
	fmt.Println("verify     >> :", valid)
	valid, err = rsa.Verify(msg, signature, fakePub)
	fmt.Println("*verify*   >> :", valid, err)
}

func naclSignDemo() {
	//nacl.sign[gen,sign,verify]
	fmt.Println("===================== ED25519 DEMO(sign,verify) =====================")
	_, fakePub := sign.GenerateKeyPair()
	msg := []byte("President Trump meets Kim Jong-un")
	fmt.Println("origin msg    :", string(msg))
	sig := sign.Sign(msg, ed25519Private)
	fmt.Println("sign       >> :", sig)
	fmt.Println("b58 signature :", base58.Encode(sig))
	valid := sign.Verify(sig, ed25519Public)
	fmt.Println("verify     >> :", valid)
	valid = sign.Verify(sig, fakePub)
	fmt.Println("*verify*   >> :", valid)
}
func caDemo() {
	//accesscontrol[gen,verify]
	fmt.Println("===================== CA DEMO(gen,verify) =====================")
	orgInfo := accesscontrol.CertInfo{
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
	fmt.Println("org information         :", orgInfo)
	rootCertObj, err := x509.ParseCertificate(rootCert.Bytes)
	rootPriObj, err := x509.ParsePKCS1PrivateKey(rootPri.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	orgCert, orgPri, err := accesscontrol.GenerateCert(rootCertObj, rootPriObj, orgInfo)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("gen org private key  >> :", orgPri)
	fmt.Println("gen org cert         >> :", orgCert)

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
	crlObj, err := x509.ParseCRL(crl.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	valid, err := accesscontrol.VerifyCert(orgCertObj, opts,crlObj)
	fmt.Println("verify               >> :", valid, err)
	opts2 := x509.VerifyOptions{
		DNSName: "www.overwatch.com",
	}
	valid, err = accesscontrol.VerifyCert(orgCertObj, opts2,crlObj)
	fmt.Println("*verify*             >> :", valid, err)

	fmt.Println("crl list                :", crlObj.TBSCertList.RevokedCertificates)
	rCert := pkix.RevokedCertificate{
		SerialNumber:   orgCertObj.SerialNumber,
		RevocationTime: time.Now(),
	}
	accesscontrol.Append2CRL(rCert, crlObj)
	fmt.Println("append to crl list   >> :", crlObj.TBSCertList.RevokedCertificates)

	valid, err = accesscontrol.VerifyCert(orgCertObj, opts,crlObj)
	fmt.Println("*verify*             >> :", valid, err)
}

func main() {
	fmt.Println(start)
	rsaDemo()
	naclSignDemo()
	caDemo()
	fmt.Println(end)
}
