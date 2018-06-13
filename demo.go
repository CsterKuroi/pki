package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/CsterKuroi/pki/common/rsa"

	"github.com/btcsuite/btcutil/base58"
)

var rsaPrivate, rsaPublic, ed25519Private, ed25519Public *pem.Block

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
}

func rsaDemo() {
	//rsa[gen,sign,verify,encrypt,decrypt]
	fakePri, fakePub := rsa.GenerateKeyPair()
	msg := []byte("The State Council decided last Wednesday to further cut tariffs on a number of imported goods starting July 1")
	fmt.Println("origin msg  :", string(msg))

	fmt.Println("===================== RSA DEMO(encrypt,decrypt) =====================")
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

}

func main() {
	rsaDemo()
	naclSignDemo()
	//nacl.sign[gen,sign,verify]
	//nacl.box[gen,seal,open]
	//nacl.secretbox[gen,seal,open]
}
