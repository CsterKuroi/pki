package box

import (
	"crypto/rand"
	"encoding/pem"
	"io"
	"log"

	"golang.org/x/crypto/nacl/box"
)

func GenerateKeyPair() (private *pem.Block, public *pem.Block) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader) // 32 32
	if err != nil {
		log.Fatal(err)
	}
	priBlock := &pem.Block{
		Type:  "CURVE25519 PRIVATE KEY",
		Bytes: privateKey[:],
	}
	if err != nil {
		log.Fatal(err)
	}
	pubBlock := &pem.Block{
		Type:  "CURVE25519 PUBLIC KEY",
		Bytes: publicKey[:],
	}
	return priBlock, pubBlock
}

func Seal(origin []byte, recipientPubBlock *pem.Block, senderPriBlock *pem.Block) []byte {
	recipientPub := new([32]byte)
	senderPri := new([32]byte)
	copy(recipientPub[:], recipientPubBlock.Bytes)
	copy(senderPri[:], senderPriBlock.Bytes)

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		log.Fatal(err)
	}

	ciphertext := box.Seal(nonce[:], origin, &nonce, recipientPub, senderPri)
	return ciphertext
}

func Open(ciphertext []byte, recipientPriBlock *pem.Block, senderPubBlock *pem.Block) ([]byte, bool) {
	recipientPri := new([32]byte)
	senderPub := new([32]byte)
	copy(recipientPri[:], recipientPriBlock.Bytes)
	copy(senderPub[:], senderPubBlock.Bytes)

	var decryptNonce [24]byte
	copy(decryptNonce[:], ciphertext[:24])

	plaintext, ok := box.Open(nil, ciphertext[24:], &decryptNonce, senderPub, recipientPri)
	return plaintext, ok
}
