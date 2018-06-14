package main

import (
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/CsterKuroi/pki/accesscontrol"
	"github.com/CsterKuroi/pki/common/nacl/sign"
	"github.com/CsterKuroi/pki/common/rsa"
	"io/ioutil"
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
func generateCARoot() {
	rootInfo := accesscontrol.CertInformation{
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

func main() {
	fmt.Println("Creating RSA Keypair...")
	generateRSAKeyPem()
	fmt.Println("Creating Ed25519 Keypair...")
	generateEd25519KeyPem()
	fmt.Println("Creating CA ROOT crt and private key...")
	generateCARoot()
}
