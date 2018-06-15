package main

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/CsterKuroi/pki/accesscontrol"
	"github.com/CsterKuroi/pki/common/nacl/box"
	"github.com/CsterKuroi/pki/common/nacl/secretbox"
	"github.com/CsterKuroi/pki/common/nacl/sign"
	"github.com/CsterKuroi/pki/common/rsa"
)

func pem2File(block *pem.Block, name string) {
	defer func() {
		buf, err := ioutil.ReadFile(name)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(buf))
	}()
	file, err := os.Create(name)
	if err != nil {
		log.Fatal(err)
	}
	err = pem.Encode(file, block)

	if err != nil {
		log.Fatal(err)
	}
}
func generateRSAKeyPem() {
	pri, pub := rsa.GenerateKeyPair()
	pem2File(pri, "./release/rsa_private.pem")
	pem2File(pub, "./release/rsa_public.pem")
}

func generateEd25519KeyPem() {
	pri, pub := sign.GenerateKeyPair()
	pem2File(pri, "./release/ed25519_private.pem")
	pem2File(pub, "./release/ed25519_public.pem")
}

func generateCurve25519KeyPem() {
	alicePri, alicePub := box.GenerateKeyPair()
	pem2File(alicePri, "./release/curve25519_alice_private.pem")
	pem2File(alicePub, "./release/curve25519_alice_public.pem")
	bobPri, bobPub := box.GenerateKeyPair()
	pem2File(bobPri, "./release/curve25519_bob_private.pem")
	pem2File(bobPub, "./release/curve25519_bob_public.pem")
}

func generatePoly1305KeyPem() {
	secret := secretbox.GenerateSecretKey()
	pem2File(secret, "./release/poly1305_secret.pem")
}

func generateCARoot() {
	rootInfo := accesscontrol.CertInfo{
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
	crt, pri, err := accesscontrol.GenerateCert(nil, nil, rootInfo)
	if err != nil {
		log.Fatal(err)
	}
	pem2File(crt, "./release/ca_root_crt.pem")
	pem2File(pri, "./release/ca_root_private.pem")
}

func generateCRL() {
	crl, err := accesscontrol.NewCRL()
	if err != nil {
		log.Fatal(err)
	}
	b, err := asn1.Marshal(*crl)

	if err != nil {
		fmt.Println(err)
	}
	crlBlock := &pem.Block{
		Type:  "X509 CRL",
		Bytes: b,
	}
	pem2File(crlBlock, "./release/ca_crl.pem")
}

func main() {
	fmt.Println("Creating RSA Keypair...")
	generateRSAKeyPem()
	fmt.Println("Creating Ed25519 Keypair...")
	generateEd25519KeyPem()
	fmt.Println("Creating Curve25519 Keypair...")
	generateCurve25519KeyPem()
	fmt.Println("Creating Poly1305 Keypair...")
	generatePoly1305KeyPem()
	fmt.Println("Creating CA ROOT crt and private key...")
	generateCARoot()
	fmt.Println("Creating CRL...")
	generateCRL()
}
