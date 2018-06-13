package sign

import (
	"crypto/rand"
	"encoding/pem"
	"log"

	"golang.org/x/crypto/nacl/sign"
)

func GenerateKeyPair() (*pem.Block, *pem.Block) {
	publicKey, privateKey, err := sign.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	priBlock := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: privateKey[:],
	}
	if err != nil {
		log.Fatal(err)
	}
	pubBlock := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: publicKey[:],
	}
	return priBlock, pubBlock
}
