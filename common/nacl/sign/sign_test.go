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
