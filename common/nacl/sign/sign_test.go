package sign

import (
	"fmt"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pri, pub := GenerateKeyPair()
	fmt.Println(pri)
	fmt.Println(pub)
}

func TestSign(t *testing.T) {
	msg := []byte("today is Thursday")
	pri, _ := GenerateKeyPair()
	sig := Sign(msg, pri)
	fmt.Println(string(sig))
}

func TestVerify(t *testing.T) {
	msg := []byte("today is Thursday")
	pri, pub := GenerateKeyPair()
	_, pub2 := GenerateKeyPair()
	sig := Sign(msg, pri)
	fmt.Println(string(sig))
	valid := Verify(sig, pub)
	fmt.Println(valid)
	valid = Verify(sig, pub2)
	fmt.Println(valid)
}
