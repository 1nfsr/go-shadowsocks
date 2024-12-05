package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"net"
	"golang.org/x/crypto/chacha20poly1305"
)

// aeadCipher implements AEAD encryption
type aeadCipher struct {
	psk      []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
	method   string
}

func (aead *aeadCipher) StreamConn(c net.Conn) net.Conn {
	return newStreamConn(c, aead)
}

func (aead *aeadCipher) GetMethod() string {
	return aead.method
}

// NewCipher creates a new cipher instance
func NewCipher(method, password string) (Cipher, error) {
	if _, ok := SupportedCiphers[method]; !ok {
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	var keySize int
	var makeAEAD func([]byte) (cipher.AEAD, error)

	switch method {
	case "chacha20-ietf-poly1305":
		keySize = chacha20poly1305.KeySize
		makeAEAD = chacha20poly1305.New
	case "aes-128-gcm":
		keySize = 16
		makeAEAD = aesGCM(16)
	case "aes-192-gcm":
		keySize = 24
		makeAEAD = aesGCM(24)
	case "aes-256-gcm":
		keySize = 32
		makeAEAD = aesGCM(32)
	}

	key := kdf(password, keySize)
	return &aeadCipher{
		psk:      key,
		makeAEAD: makeAEAD,
		method:   method,
	}, nil
}

func aesGCM(keySize int) func(key []byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
}
 