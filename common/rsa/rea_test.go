package rsa

import (
	"fmt"
	"log"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pri, pub := GenerateKeyPair()
	fmt.Println(pri)
	fmt.Println(pub)
}

func TestEncrypt(t *testing.T) {
	msg := []byte("hello pki and rsa")
	pri, pub := GenerateKeyPair()
	fmt.Println(pri)
	fmt.Println(pub)
	cipher, err := Encrypt(msg, pub)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cipher)
}

func TestDecrypt(t *testing.T) {
	msg := []byte("hello pki and rsa")
	fmt.Println(string(msg))
	pri, pub := GenerateKeyPair()
	fmt.Println(pri)
	fmt.Println(pub)
	cipher, err := Encrypt(msg, pub)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cipher)
	plain, err := Decrypt(cipher, pri)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(plain))
}
