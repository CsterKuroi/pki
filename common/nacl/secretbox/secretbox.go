package secretbox

import (
	"crypto/rand"
	"encoding/pem"
	"io"
	"log"

	"golang.org/x/crypto/nacl/secretbox"
)

func GenerateSecretKey() (secret *pem.Block) {
	var secretKey [32]byte
	if _, err := io.ReadFull(rand.Reader, secretKey[:]); err != nil {
		panic(err)
	}

	secretBlock := &pem.Block{
		Type:  "POLY1305 KEY",
		Bytes: secretKey[:],
	}
	return secretBlock
}

func Seal(origin []byte, secretBlock *pem.Block) []byte {
	var secret [32]byte
	copy(secret[:], secretBlock.Bytes)

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		log.Fatal(err)
	}

	ciphertext := secretbox.Seal(nonce[:], origin, &nonce, &secret)
	return ciphertext
}

func Open(ciphertext []byte, secretBlock *pem.Block) ([]byte, bool) {
	var secret [32]byte
	copy(secret[:], secretBlock.Bytes)

	var decryptNonce [24]byte
	copy(decryptNonce[:], ciphertext[:24])

	plaintext, ok := secretbox.Open(nil, ciphertext[24:], &decryptNonce, &secret)
	return plaintext, ok
}
