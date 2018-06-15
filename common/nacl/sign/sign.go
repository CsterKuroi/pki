package sign

import (
	"crypto/rand"
	"encoding/pem"
	"log"

	"golang.org/x/crypto/nacl/sign"
)

func GenerateKeyPair() (private *pem.Block, public *pem.Block) {
	publicKey, privateKey, err := sign.GenerateKey(rand.Reader) // 32 64
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

func Sign(origin []byte, priBlock *pem.Block) []byte {
	privateKey := new([64]byte)
	copy((*privateKey)[:], priBlock.Bytes)
	signature := sign.Sign(nil, origin, privateKey)
	return signature
}

func Verify(signature []byte, pubBlock *pem.Block) bool {
	publicKey := new([32]byte)
	copy((*publicKey)[:], pubBlock.Bytes)
	_, valid := sign.Open(nil, signature, publicKey)
	return valid
}
