package main

import (
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/CsterKuroi/pki/common/nacl/sign"
	"github.com/CsterKuroi/pki/common/rsa"
)

func pem2File(block *pem.Block, name string) {
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
	pri, pub := rsa.GenerateKeyPair()
	fmt.Println(pri)
	fmt.Println(pub)
}

func generatePoly1305KeyPem() {
	pri, pub := rsa.GenerateKeyPair()
	fmt.Println(pri)
	fmt.Println(pub)
}

func main() {
	fmt.Println("Creating RSA Keypair...")
	generateRSAKeyPem()
	fmt.Println("Creating Ed25519 Keypair...")
	generateEd25519KeyPem()
	//fmt.Println("Creating Curve25519 Keypair...")
	//generateCurve25519KeyPem()
	//fmt.Println("Creating Poly1305 Secret Key...")
	//generatePoly1305KeyPem()
}
