package box

import (
	"fmt"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	alicePri, alicePub := GenerateKeyPair()
	fmt.Println(alicePub, alicePri)
}

func TestSeal(t *testing.T) {
	msg := []byte("today is Friday")
	fmt.Println(string(msg))
	alicePri, alicePub := GenerateKeyPair()
	fmt.Println(alicePub, alicePri)

	bobPri, bobPub := GenerateKeyPair()
	fmt.Println(bobPub, bobPri)

	cipher := Seal(msg, bobPub, alicePri)
	fmt.Println(cipher)
}

func TestOpen(t *testing.T) {
	msg := []byte("today is Friday")
	fmt.Println(string(msg))
	alicePri, alicePub := GenerateKeyPair()
	fmt.Println(alicePub, alicePri)

	bobPri, bobPub := GenerateKeyPair()
	fmt.Println(bobPub, bobPri)

	cipher := Seal(msg, bobPub, alicePri)
	fmt.Println(cipher)

	plain, ok := Open(cipher, bobPri, alicePub)
	fmt.Println(string(plain), ok)
}
