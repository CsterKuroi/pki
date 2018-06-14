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
	pri2, _ := GenerateKeyPair()
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
	plain, err = Decrypt(cipher, pri2)
	fmt.Println(string(plain), err)
}

func TestSign(t *testing.T) {
	msg := []byte("hello pki and rsa sign")
	fmt.Println(string(msg))
	pri, _ := GenerateKeyPair()
	sig, err := Sign(msg, pri)
	fmt.Println(sig, err)
}

func TestVerify(t *testing.T) {
	msg := []byte("hello pki and rsa sign")
	fmt.Println(string(msg))
	pri, pub := GenerateKeyPair()
	_, pub2 := GenerateKeyPair()
	sig, err := Sign(msg, pri)
	fmt.Println(sig, err)
	valid, err := Verify(msg, sig, pub)
	fmt.Println(valid, err)
	valid, err = Verify(msg, sig, pub2)
	fmt.Println(valid, err)

}
