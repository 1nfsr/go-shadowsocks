package cipher

import (
	"fmt"
	"log"
	"net"
	
	"github.com/shadowsocks/go-shadowsocks2/core"
)

type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	StreamConn(conn net.Conn) net.Conn
	GetMethod() string
}

type shadowCipher struct {
    cipher   core.Cipher
    method   string
    password string
}

func NewCipher(method, password string) (*shadowCipher, error) {
    log.Printf("Debug: Creating cipher with method=%s", method)
    
    ciph, err := core.PickCipher(method, nil, password)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %v", err)
    }
    
    return &shadowCipher{
        cipher:   ciph,
        method:   method,
        password: password,
    }, nil
}

func (c *shadowCipher) Encrypt(plaintext []byte) ([]byte, error) {
    return nil, fmt.Errorf("not implemented")
}

func (c *shadowCipher) Decrypt(ciphertext []byte) ([]byte, error) {
    return nil, fmt.Errorf("not implemented")
}

func (c *shadowCipher) StreamConn(conn net.Conn) net.Conn {
    return c.cipher.StreamConn(conn)
}

func (c *shadowCipher) GetMethod() string {
    return c.method
}
