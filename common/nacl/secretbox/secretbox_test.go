package secretbox

import (
	"fmt"
	"testing"
)

func TestGenerateSecretKey(t *testing.T) {
	b := GenerateSecretKey()
	fmt.Println(b)
}

func TestSeal(t *testing.T) {
	msg := []byte("today is Friday")
	b := GenerateSecretKey()
	fmt.Println(b)

	cipher := Seal(msg, b)
	fmt.Println(cipher)
}

func TestOpen(t *testing.T) {
	msg := []byte("today is Friday")
	fmt.Println(string(msg))
	b := GenerateSecretKey()
	fmt.Println(b)

	cipher := Seal(msg, b)
	fmt.Println(cipher)

	plain, ok := Open(cipher, b)
	fmt.Println(string(plain), ok)
}
