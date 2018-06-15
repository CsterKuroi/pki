package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"log"
)

func GenerateKeyPair() (private *pem.Block, public *pem.Block) {
	bits := 1024
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	priBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	pub, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	pubBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pub,
	}
	return priBlock, pubBlock
}

func Encrypt(origin []byte, pubBlock *pem.Block) ([]byte, error) {
	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origin)
}

func Decrypt(ciphertext []byte, priBlock *pem.Block) ([]byte, error) {
	pri, err := x509.ParsePKCS1PrivateKey(priBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, pri, ciphertext)
}

func Sign(origin []byte, priBlock *pem.Block) ([]byte, error) {
	h := sha256.New()
	h.Write(origin)
	hashed := h.Sum(nil)
	pri, err := x509.ParsePKCS1PrivateKey(priBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, pri, crypto.SHA256, hashed)
}

func Verify(origin, signature []byte, pubBlock *pem.Block) (bool, error) {
	hashed := sha256.Sum256(origin)
	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return false, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false, err
	}
	return true, err
}
